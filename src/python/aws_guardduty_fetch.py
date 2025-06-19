#!/usr/bin/env python3
"""aws_guardduty_fetch.py – Fetch active GuardDuty findings

Requires:
    pip install boto3
    AWS credentials configured (env vars or ~/.aws/credentials)
Usage:
    python3 aws_guardduty_fetch.py <region>
"""
import sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def list_detectors(region):
    client = boto3.client('guardduty', region_name=region)
    return client.list_detectors()['DetectorIds']


def list_findings(detector_id, region):
    client = boto3.client('guardduty', region_name=region)
    return client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'service.archived': {'Eq': ['false']},
                'severity': {'Gte': 4}
            }
        },
        MaxResults=20
    )['FindingIds']


def get_findings(detector_id, finding_ids, region):
    client = boto3.client('guardduty', region_name=region)
    return client.get_findings(DetectorId=detector_id, FindingIds=finding_ids)['Findings']


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 aws_guardduty_fetch.py <region>')
        sys.exit(1)
    region = sys.argv[1]

    try:
        for det in list_detectors(region):
            fids = list_findings(det, region)
            if not fids:
                print('[+] No active findings')
                continue
            findings = get_findings(det, fids, region)
            for f in findings:
                print(f"[{f['Severity']}] {f['Title']} – {f['Description']}")
    except (BotoCoreError, ClientError) as e:
        print('AWS error:', e)
        sys.exit(1)


if __name__ == '__main__':
    main()
