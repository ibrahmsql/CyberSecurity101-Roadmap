// ElasticSearch Security Toolkit in Node.js
// Install: npm install @elastic/elasticsearch axios
// Usage: node elastic_security.js [command] [options]
// Example: node elastic_security.js search localhost:9200 logs "error"

const { Client } = require('@elastic/elasticsearch');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

class ElasticSecurityToolkit {
    constructor(host, username = null, password = null) {
        this.host = host;
        this.client = new Client({
            node: `http://${host}`,
            auth: username && password ? { username, password } : undefined
        });
    }

    async getClusterInfo() {
        try {
            console.log('[+] Getting cluster information...');
            const info = await this.client.info();
            const health = await this.client.cluster.health();
            const stats = await this.client.cluster.stats();

            console.log('\n=== Cluster Information ===');
            console.log(`Name: ${info.body.name}`);
            console.log(`Version: ${info.body.version.number}`);
            console.log(`Cluster Name: ${info.body.cluster_name}`);
            console.log(`Status: ${health.body.status}`);
            console.log(`Nodes: ${health.body.number_of_nodes}`);
            console.log(`Data Nodes: ${health.body.number_of_data_nodes}`);
            console.log(`Active Shards: ${health.body.active_shards}`);
            console.log(`Indices: ${stats.body.indices.count}`);
            console.log(`Documents: ${stats.body.indices.docs.count}`);
            console.log(`Store Size: ${this.formatBytes(stats.body.indices.store.size_in_bytes)}`);
        } catch (error) {
            console.error('Error getting cluster info:', error.message);
        }
    }

    async listIndices() {
        try {
            console.log('[+] Listing indices...');
            const response = await this.client.cat.indices({ format: 'json' });
            
            console.log('\n=== Indices ===');
            response.body.forEach(index => {
                console.log(`${index.index}:`);
                console.log(`  Health: ${index.health}`);
                console.log(`  Status: ${index.status}`);
                console.log(`  Documents: ${index['docs.count']}`);
                console.log(`  Size: ${index['store.size']}`);
                console.log();
            });
        } catch (error) {
            console.error('Error listing indices:', error.message);
        }
    }

    async searchLogs(index, query, size = 100) {
        try {
            console.log(`[+] Searching in index '${index}' for: ${query}`);
            
            const searchBody = {
                size: size,
                query: {
                    bool: {
                        should: [
                            { match: { message: query } },
                            { match: { log: query } },
                            { match: { content: query } },
                            { wildcard: { "*": `*${query}*` } }
                        ]
                    }
                },
                sort: [{ '@timestamp': { order: 'desc' } }]
            };

            const response = await this.client.search({
                index: index,
                body: searchBody
            });

            console.log(`\n=== Search Results (${response.body.hits.total.value} total) ===`);
            response.body.hits.hits.forEach((hit, idx) => {
                console.log(`\n[${idx + 1}] Score: ${hit._score}`);
                console.log(`Index: ${hit._index}`);
                console.log(`ID: ${hit._id}`);
                console.log('Source:');
                console.log(JSON.stringify(hit._source, null, 2));
                console.log('-'.repeat(80));
            });
        } catch (error) {
            console.error('Error searching:', error.message);
        }
    }

    async findSecurityEvents(index) {
        try {
            console.log(`[+] Searching for security events in '${index}'...`);
            
            const securityQueries = [
                { name: 'Failed Logins', query: { match: { message: 'failed login' } } },
                { name: 'Authentication Errors', query: { match: { message: 'authentication failed' } } },
                { name: 'Privilege Escalation', query: { match: { message: 'privilege escalation' } } },
                { name: 'Suspicious Commands', query: { terms: { command: ['sudo', 'su', 'passwd', 'chmod 777'] } } },
                { name: 'Network Anomalies', query: { range: { bytes: { gte: 1000000 } } } },
                { name: 'Error Logs', query: { match: { level: 'ERROR' } } }
            ];

            for (const sq of securityQueries) {
                try {
                    const response = await this.client.search({
                        index: index,
                        body: {
                            size: 10,
                            query: sq.query,
                            sort: [{ '@timestamp': { order: 'desc' } }]
                        }
                    });

                    if (response.body.hits.total.value > 0) {
                        console.log(`\n=== ${sq.name} (${response.body.hits.total.value} found) ===`);
                        response.body.hits.hits.slice(0, 5).forEach((hit, idx) => {
                            console.log(`[${idx + 1}] ${hit._source.timestamp || hit._source['@timestamp'] || 'No timestamp'}`);
                            console.log(`    ${hit._source.message || hit._source.log || JSON.stringify(hit._source).substring(0, 100)}...`);
                        });
                    }
                } catch (err) {
                    console.log(`No results for ${sq.name}`);
                }
            }
        } catch (error) {
            console.error('Error finding security events:', error.message);
        }
    }

    async analyzeTraffic(index) {
        try {
            console.log(`[+] Analyzing network traffic in '${index}'...`);
            
            // Top source IPs
            const topSrcIPs = await this.client.search({
                index: index,
                body: {
                    size: 0,
                    aggs: {
                        top_src_ips: {
                            terms: {
                                field: 'src_ip.keyword',
                                size: 10
                            }
                        }
                    }
                }
            });

            console.log('\n=== Top Source IPs ===');
            if (topSrcIPs.body.aggregations && topSrcIPs.body.aggregations.top_src_ips) {
                topSrcIPs.body.aggregations.top_src_ips.buckets.forEach((bucket, idx) => {
                    console.log(`${idx + 1}. ${bucket.key}: ${bucket.doc_count} requests`);
                });
            }

            // Top destinations
            const topDstPorts = await this.client.search({
                index: index,
                body: {
                    size: 0,
                    aggs: {
                        top_dst_ports: {
                            terms: {
                                field: 'dst_port',
                                size: 10
                            }
                        }
                    }
                }
            });

            console.log('\n=== Top Destination Ports ===');
            if (topDstPorts.body.aggregations && topDstPorts.body.aggregations.top_dst_ports) {
                topDstPorts.body.aggregations.top_dst_ports.buckets.forEach((bucket, idx) => {
                    console.log(`${idx + 1}. Port ${bucket.key}: ${bucket.doc_count} connections`);
                });
            }
        } catch (error) {
            console.error('Error analyzing traffic:', error.message);
        }
    }

    async exportData(index, query, outputFile) {
        try {
            console.log(`[+] Exporting data from '${index}' to '${outputFile}'...`);
            
            const response = await this.client.search({
                index: index,
                body: {
                    size: 10000,
                    query: query ? { match: { message: query } } : { match_all: {} },
                    sort: [{ '@timestamp': { order: 'desc' } }]
                }
            });

            const data = response.body.hits.hits.map(hit => ({
                index: hit._index,
                id: hit._id,
                score: hit._score,
                source: hit._source
            }));

            fs.writeFileSync(outputFile, JSON.stringify(data, null, 2));
            console.log(`Exported ${data.length} records to ${outputFile}`);
        } catch (error) {
            console.error('Error exporting data:', error.message);
        }
    }

    async checkSecurity() {
        try {
            console.log('[+] Performing security checks...');
            
            // Check if authentication is enabled
            try {
                await axios.get(`http://${this.host}/_cluster/health`);
                console.log('[!] WARNING: Elasticsearch appears to be accessible without authentication');
            } catch (error) {
                if (error.response && error.response.status === 401) {
                    console.log('[+] Good: Authentication is required');
                } else {
                    console.log('[?] Could not determine authentication status');
                }
            }

            // Check for common security indices
            const securityIndices = ['.security', '.security-6', '.security-7', 'wazuh-*', 'logstash-*'];
            const indices = await this.client.cat.indices({ format: 'json' });
            const indexNames = indices.body.map(idx => idx.index);

            console.log('\n=== Security-related Indices ===');
            securityIndices.forEach(pattern => {
                const matches = indexNames.filter(name => 
                    pattern.includes('*') ? 
                    name.startsWith(pattern.replace('*', '')) : 
                    name === pattern
                );
                if (matches.length > 0) {
                    console.log(`[+] Found: ${matches.join(', ')}`);
                } else {
                    console.log(`[-] Not found: ${pattern}`);
                }
            });
        } catch (error) {
            console.error('Error checking security:', error.message);
        }
    }

    formatBytes(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }
}

function printUsage() {
    console.log('ElasticSearch Security Toolkit');
    console.log('Usage: node elastic_security.js [command] [options]\n');
    console.log('Commands:');
    console.log('  info <host>                          - Get cluster information');
    console.log('  indices <host>                       - List all indices');
    console.log('  search <host> <index> <query> [size] - Search logs');
    console.log('  security <host> <index>              - Find security events');
    console.log('  traffic <host> <index>               - Analyze network traffic');
    console.log('  export <host> <index> [query] <file> - Export data to JSON');
    console.log('  check <host>                         - Perform security checks');
    console.log('\nExamples:');
    console.log('  node elastic_security.js info localhost:9200');
    console.log('  node elastic_security.js search localhost:9200 logstash-* "error" 50');
    console.log('  node elastic_security.js security localhost:9200 security-logs');
    console.log('  node elastic_security.js export localhost:9200 logs "failed" output.json');
}

async function main() {
    if (process.argv.length < 4) {
        printUsage();
        process.exit(1);
    }

    const command = process.argv[2];
    const host = process.argv[3];
    
    const toolkit = new ElasticSecurityToolkit(host);

    try {
        switch (command) {
            case 'info':
                await toolkit.getClusterInfo();
                break;
                
            case 'indices':
                await toolkit.listIndices();
                break;
                
            case 'search':
                if (process.argv.length < 6) {
                    console.log('Usage: search <host> <index> <query> [size]');
                    process.exit(1);
                }
                const index = process.argv[4];
                const query = process.argv[5];
                const size = process.argv[6] ? parseInt(process.argv[6]) : 100;
                await toolkit.searchLogs(index, query, size);
                break;
                
            case 'security':
                if (process.argv.length < 5) {
                    console.log('Usage: security <host> <index>');
                    process.exit(1);
                }
                await toolkit.findSecurityEvents(process.argv[4]);
                break;
                
            case 'traffic':
                if (process.argv.length < 5) {
                    console.log('Usage: traffic <host> <index>');
                    process.exit(1);
                }
                await toolkit.analyzeTraffic(process.argv[4]);
                break;
                
            case 'export':
                if (process.argv.length < 6) {
                    console.log('Usage: export <host> <index> [query] <file>');
                    process.exit(1);
                }
                const exportIndex = process.argv[4];
                let exportQuery = null;
                let outputFile;
                
                if (process.argv.length === 6) {
                    outputFile = process.argv[5];
                } else {
                    exportQuery = process.argv[5];
                    outputFile = process.argv[6];
                }
                
                await toolkit.exportData(exportIndex, exportQuery, outputFile);
                break;
                
            case 'check':
                await toolkit.checkSecurity();
                break;
                
            default:
                console.log(`Unknown command: ${command}`);
                printUsage();
                break;
        }
    } catch (error) {
        console.error('Error:', error.message);
    }
}

if (require.main === module) {
    main();
}

module.exports = ElasticSecurityToolkit;