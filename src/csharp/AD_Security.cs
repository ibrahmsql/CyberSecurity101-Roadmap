// Active Directory Security Toolkit in C#
// Build: dotnet new console -n ADSecurityToolkit && mv AD_Security.cs ADSecurityToolkit/Program.cs && cd ADSecurityToolkit && dotnet run
// Usage: dotnet run -- [command] [options]
// Requirements: Windows domain environment with appropriate permissions

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;
using System.Text;

class ADSecurityToolkit
{
    private string domain;
    private DirectoryEntry rootEntry;
    
    public ADSecurityToolkit(string domainName)
    {
        domain = domainName;
        rootEntry = new DirectoryEntry($"LDAP://{domain}");
    }
    
    public void EnumerateUsers(int limit = 50)
    {
        Console.WriteLine($"[+] Enumerating users in {domain} (limit: {limit})");
        
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            searcher.Filter = "(&(objectClass=user)(objectCategory=person))";
            searcher.SizeLimit = limit;
            searcher.PropertiesToLoad.AddRange(new string[] {
                "sAMAccountName", "displayName", "mail", "lastLogon",
                "pwdLastSet", "userAccountControl", "memberOf", "description"
            });
            
            foreach (SearchResult result in searcher.FindAll())
            {
                string samAccount = GetProperty(result, "sAMAccountName");
                string displayName = GetProperty(result, "displayName");
                string email = GetProperty(result, "mail");
                string description = GetProperty(result, "description");
                
                Console.WriteLine($"User: {samAccount}");
                if (!string.IsNullOrEmpty(displayName))
                    Console.WriteLine($"  Display Name: {displayName}");
                if (!string.IsNullOrEmpty(email))
                    Console.WriteLine($"  Email: {email}");
                if (!string.IsNullOrEmpty(description))
                    Console.WriteLine($"  Description: {description}");
                
                // Check if account is disabled
                if (result.Properties["userAccountControl"].Count > 0)
                {
                    int uac = (int)result.Properties["userAccountControl"][0];
                    if ((uac & 0x2) != 0)
                        Console.WriteLine($"  Status: DISABLED");
                }
                
                Console.WriteLine();
            }
        }
    }
    
    public void EnumerateGroups(int limit = 50)
    {
        Console.WriteLine($"[+] Enumerating groups in {domain} (limit: {limit})");
        
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            searcher.Filter = "(objectClass=group)";
            searcher.SizeLimit = limit;
            searcher.PropertiesToLoad.AddRange(new string[] {
                "sAMAccountName", "displayName", "description", "member", "groupType"
            });
            
            foreach (SearchResult result in searcher.FindAll())
            {
                string samAccount = GetProperty(result, "sAMAccountName");
                string displayName = GetProperty(result, "displayName");
                string description = GetProperty(result, "description");
                int memberCount = result.Properties["member"].Count;
                
                Console.WriteLine($"Group: {samAccount}");
                if (!string.IsNullOrEmpty(displayName))
                    Console.WriteLine($"  Display Name: {displayName}");
                if (!string.IsNullOrEmpty(description))
                    Console.WriteLine($"  Description: {description}");
                Console.WriteLine($"  Members: {memberCount}");
                Console.WriteLine();
            }
        }
    }
    
    public void EnumerateComputers(int limit = 50)
    {
        Console.WriteLine($"[+] Enumerating computers in {domain} (limit: {limit})");
        
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            searcher.Filter = "(objectClass=computer)";
            searcher.SizeLimit = limit;
            searcher.PropertiesToLoad.AddRange(new string[] {
                "sAMAccountName", "dNSHostName", "operatingSystem",
                "operatingSystemVersion", "lastLogon", "description"
            });
            
            foreach (SearchResult result in searcher.FindAll())
            {
                string samAccount = GetProperty(result, "sAMAccountName");
                string dnsName = GetProperty(result, "dNSHostName");
                string os = GetProperty(result, "operatingSystem");
                string osVersion = GetProperty(result, "operatingSystemVersion");
                string description = GetProperty(result, "description");
                
                Console.WriteLine($"Computer: {samAccount}");
                if (!string.IsNullOrEmpty(dnsName))
                    Console.WriteLine($"  DNS Name: {dnsName}");
                if (!string.IsNullOrEmpty(os))
                    Console.WriteLine($"  OS: {os} {osVersion}");
                if (!string.IsNullOrEmpty(description))
                    Console.WriteLine($"  Description: {description}");
                Console.WriteLine();
            }
        }
    }
    
    public void FindPrivilegedUsers()
    {
        Console.WriteLine($"[+] Finding privileged users in {domain}");
        
        string[] privilegedGroups = {
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Administrators", "Account Operators", "Backup Operators",
            "Server Operators", "Print Operators"
        };
        
        foreach (string groupName in privilegedGroups)
        {
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
                {
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("member");
                    
                    SearchResult groupResult = searcher.FindOne();
                    if (groupResult != null && groupResult.Properties["member"].Count > 0)
                    {
                        Console.WriteLine($"\n--- {groupName} ---");
                        foreach (string memberDN in groupResult.Properties["member"])
                        {
                            try
                            {
                                using (DirectoryEntry memberEntry = new DirectoryEntry($"LDAP://{memberDN}"))
                                {
                                    string samAccount = memberEntry.Properties["sAMAccountName"].Value?.ToString();
                                    string displayName = memberEntry.Properties["displayName"].Value?.ToString();
                                    Console.WriteLine($"  {samAccount} ({displayName})");
                                }
                            }
                            catch { /* Skip inaccessible members */ }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error querying {groupName}: {ex.Message}");
            }
        }
    }
    
    public void FindServiceAccounts()
    {
        Console.WriteLine($"[+] Finding service accounts in {domain}");
        
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))";
            searcher.PropertiesToLoad.AddRange(new string[] {
                "sAMAccountName", "displayName", "servicePrincipalName", "description"
            });
            
            foreach (SearchResult result in searcher.FindAll())
            {
                string samAccount = GetProperty(result, "sAMAccountName");
                string displayName = GetProperty(result, "displayName");
                string description = GetProperty(result, "description");
                
                Console.WriteLine($"Service Account: {samAccount}");
                if (!string.IsNullOrEmpty(displayName))
                    Console.WriteLine($"  Display Name: {displayName}");
                if (!string.IsNullOrEmpty(description))
                    Console.WriteLine($"  Description: {description}");
                
                Console.WriteLine("  SPNs:");
                foreach (string spn in result.Properties["servicePrincipalName"])
                {
                    Console.WriteLine($"    {spn}");
                }
                Console.WriteLine();
            }
        }
    }
    
    public void GetDomainInfo()
    {
        Console.WriteLine($"[+] Domain Information for {domain}");
        
        try
        {
            DirectoryContext ctx = new DirectoryContext(DirectoryContextType.Domain, domain);
            Domain dom = Domain.GetDomain(ctx);
            
            Console.WriteLine($"Domain Name: {dom.Name}");
            Console.WriteLine($"Forest: {dom.Forest.Name}");
            
            Console.WriteLine("\nDomain Controllers:");
            foreach (DomainController dc in dom.DomainControllers)
            {
                Console.WriteLine($"  {dc.Name} - {dc.IPAddress}");
            }
            
            Console.WriteLine("\nTrust Relationships:");
            foreach (TrustRelationshipInformation trust in dom.GetAllTrustRelationships())
            {
                Console.WriteLine($"  {trust.TargetName} ({trust.TrustType}, {trust.TrustDirection})");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting domain info: {ex.Message}");
        }
    }
    
    public void FindWeakPasswords()
    {
        Console.WriteLine($"[+] Finding accounts with weak password policies in {domain}");
        
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            searcher.Filter = "(&(objectClass=user)(objectCategory=person))";
            searcher.PropertiesToLoad.AddRange(new string[] {
                "sAMAccountName", "userAccountControl", "pwdLastSet", "badPwdCount"
            });
            
            foreach (SearchResult result in searcher.FindAll())
            {
                string samAccount = GetProperty(result, "sAMAccountName");
                
                if (result.Properties["userAccountControl"].Count > 0)
                {
                    int uac = (int)result.Properties["userAccountControl"][0];
                    
                    // Check for password never expires
                    if ((uac & 0x10000) != 0)
                    {
                        Console.WriteLine($"[!] {samAccount}: Password never expires");
                    }
                    
                    // Check for password not required
                    if ((uac & 0x20) != 0)
                    {
                        Console.WriteLine($"[!] {samAccount}: Password not required");
                    }
                    
                    // Check for reversible encryption
                    if ((uac & 0x80) != 0)
                    {
                        Console.WriteLine($"[!] {samAccount}: Reversible encryption enabled");
                    }
                }
                
                // Check for accounts that haven't changed password in a long time
                if (result.Properties["pwdLastSet"].Count > 0)
                {
                    long pwdLastSet = (long)result.Properties["pwdLastSet"][0];
                    if (pwdLastSet > 0)
                    {
                        DateTime lastSet = DateTime.FromFileTime(pwdLastSet);
                        if ((DateTime.Now - lastSet).TotalDays > 365)
                        {
                            Console.WriteLine($"[!] {samAccount}: Password not changed for {(DateTime.Now - lastSet).TotalDays:F0} days");
                        }
                    }
                }
            }
        }
    }
    
    private string GetProperty(SearchResult result, string propertyName)
    {
        if (result.Properties[propertyName].Count > 0)
            return result.Properties[propertyName][0].ToString();
        return string.Empty;
    }
    
    public void Dispose()
    {
        rootEntry?.Dispose();
    }
}

class Program
{
    static void PrintUsage(string programName)
    {
        Console.WriteLine("Active Directory Security Toolkit");
        Console.WriteLine($"Usage: {programName} [command] [options]\n");
        Console.WriteLine("Commands:");
        Console.WriteLine("  info <domain>                    - Get domain information");
        Console.WriteLine("  users <domain> [limit]           - Enumerate users");
        Console.WriteLine("  groups <domain> [limit]          - Enumerate groups");
        Console.WriteLine("  computers <domain> [limit]       - Enumerate computers");
        Console.WriteLine("  privileged <domain>              - Find privileged users");
        Console.WriteLine("  services <domain>                - Find service accounts");
        Console.WriteLine("  weakpwd <domain>                 - Find weak password policies");
        Console.WriteLine("\nExamples:");
        Console.WriteLine($"  {programName} info contoso.com");
        Console.WriteLine($"  {programName} users contoso.com 100");
        Console.WriteLine($"  {programName} privileged contoso.com");
    }
    
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            PrintUsage("ADSecurityToolkit");
            return;
        }
        
        string command = args[0].ToLower();
        string domain = args[1];
        
        ADSecurityToolkit toolkit = null;
        
        try
        {
            toolkit = new ADSecurityToolkit(domain);
            
            switch (command)
            {
                case "info":
                    toolkit.GetDomainInfo();
                    break;
                    
                case "users":
                    int userLimit = args.Length > 2 ? int.Parse(args[2]) : 50;
                    toolkit.EnumerateUsers(userLimit);
                    break;
                    
                case "groups":
                    int groupLimit = args.Length > 2 ? int.Parse(args[2]) : 50;
                    toolkit.EnumerateGroups(groupLimit);
                    break;
                    
                case "computers":
                    int computerLimit = args.Length > 2 ? int.Parse(args[2]) : 50;
                    toolkit.EnumerateComputers(computerLimit);
                    break;
                    
                case "privileged":
                    toolkit.FindPrivilegedUsers();
                    break;
                    
                case "services":
                    toolkit.FindServiceAccounts();
                    break;
                    
                case "weakpwd":
                    toolkit.FindWeakPasswords();
                    break;
                    
                default:
                    Console.WriteLine($"Unknown command: {command}");
                    PrintUsage("ADSecurityToolkit");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            toolkit?.Dispose();
        }
    }
}
