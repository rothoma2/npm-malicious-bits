#!/usr/bin/env python3
"""
NPM Malicious IOCs CLI Tool

A command-line tool for collecting and managing NPM malicious Indicators
of Compromise (IOCs).
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pprint import pprint
from pathlib import Path
from typing import Optional
from .models import AffectedPackage, MaliciousPackageReport


def parse_malicious_json_files(folder_path: str) -> MaliciousPackageReport:
    """
    Traverse a folder and parse all JSON files to extract affected package
    ecosystem information.

    Args:
        folder_path: Path to the folder to traverse

    Returns:
        MaliciousPackageReport containing all found packages and statistics
    """
    debugFlag = True

    folder_path_obj = Path(folder_path)

    if not folder_path_obj.exists():
        raise FileNotFoundError(f"Folder not found: {folder_path}")

    if not folder_path_obj.is_dir():
        raise ValueError(f"Path is not a directory: {folder_path}")

    packages = []
    files_processed = 0

    print(f"Scanning {folder_path} for JSON files...")

    for json_file in folder_path_obj.rglob("MAL*.json"):

        files_processed += 1
        try:
            
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if debugFlag:
                pprint(data)
                debugFlag = False


            published = data.get('published')
            affected = data.get('affected', [])
            versions = data.get('versions', [])

            for affected_item in affected:
                
                package_info = affected_item.get('package', {})
                ecosystem = package_info.get('ecosystem')
                
                if ecosystem:
                    package = AffectedPackage(
                        ecosystem=ecosystem,
                        published=published,
                        package_name=package_info.get('name'),
                        versions=versions
                    )
                    packages.append(package)

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Warning: Could not parse {json_file}: {e}")
            continue
 
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            continue

    report = MaliciousPackageReport(
        packages=packages,
        total_files_processed=files_processed,
        total_packages_found=len(packages)
    )

    print(f"Processing complete: {files_processed} files processed, "
          f"{len(packages)} packages found")

    print(f"Ecosystems found: {', '.join(report.get_ecosystems())}")

    return report


def parse_recent_malicious_json_files(folder_path: str, hours: int = 72) -> MaliciousPackageReport:
    """
    Parse JSON files filtering for those published within the specified hours.
    
    Args:
        folder_path: Path to the folder to traverse
        hours: Number of hours to look back (default: 72)
    
    Returns:
        MaliciousPackageReport containing only recent packages
    """
    report = parse_malicious_json_files(folder_path)
    
    recent_packages = report.get_packages_within_hours(hours)
    #print(type(recent_packages))
    #pprint(recent_packages)
    #print(len(recent_packages))
    
    filtered_report = MaliciousPackageReport(
        packages=recent_packages,
        total_files_processed=report.total_files_processed,
        total_packages_found=len(recent_packages)
    )
    
    print(f"Found {len(recent_packages)} packages published within "
          f"the last {hours} hours")
    
    for package in recent_packages:
        print(f"- {package.ecosystem} - {package.package_name} ")
    
    return filtered_report


def collect_iocs(output: Optional[str] = None) -> None:
    """
    Collect malicious NPM IOCs from OSSF repository.

    Args:
        output: The output file to save IOCs to
    """
    print("Collecting NPM malicious IOCs...")

    report = None

    print("Including OSSF malicious packages repository...")
    temp_dir = clone_ossf_malicious_packages()
    if temp_dir:
        malicious_path = os.path.join(temp_dir, "osv", "malicious")
        if os.path.exists(malicious_path):
            report = parse_malicious_json_files(malicious_path)
            print(f"Analysis complete: {report}")
        else:
            print("Warning: Could not find malicious packages folder")

    if output and report:
        print(f"Saving IOCs to: {output}")
        with open(output, 'w') as f:
            f.write(report.to_json())
        print(f"Results saved to {output}")

    elif report:
        print("IOCs collected successfully (no output file specified)")
    else:
        print("No IOCs collected")


def clone_ossf_malicious_packages(local_path: Optional[str] = None) -> Optional[str]:  # noqa: E501
    """
    Clone the OSSF malicious packages repository and return the local path.
    
    Args:
        local_path: Path where to clone the repository. If None, uses temp dir.
        
    Returns:
        Local path to the cloned repository, or None if cloning failed
    """

    ossf_repo_url = "https://github.com/ossf/malicious-packages"
    
    if local_path is None:
        local_path = tempfile.mkdtemp(prefix="ossf_malicious_packages_")
        print(f"Cloning to temporary directory: {local_path}")
    else:
        print(f"Cloning to: {local_path}")
    
    try:
        print(f"Cloning {ossf_repo_url}...")
        subprocess.run(
            ["git", "clone", ossf_repo_url, local_path],
            capture_output=True,
            text=True,
            check=True
        )
        print("Repository cloned successfully!")
        
        # Count JSON files in /osv/malicious/ folder
        malicious_path = os.path.join(local_path, "osv", "malicious")
        json_count = 0
        
        if os.path.exists(malicious_path):

            print(f"Scanning {malicious_path} for JSON files...")
            for root, dirs, files in os.walk(malicious_path):
                for file_name in files:
                    if file_name.lower().endswith('.json'):

                        json_count += 1
            
            print(f"Found {json_count} JSON files in /osv/malicious/ folder")
        else:
            print("Warning: /osv/malicious/ folder not found in repository")
        
        return local_path
        
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        print(f"Command output: {e.stderr}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='npm-iocs',
        description='NPM Malicious IOCs CLI Tool - Collect and manage '
                    'NPM malicious indicators',
        epilog='For more information, visit: '
               'https://github.com/rothoma2/npm-malicious-bits'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.1.0'
    )

    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='COMMAND'
    )

    # Collect command
    collect_parser = subparsers.add_parser(
        'collect',
        help='Collect malicious IOCs from OSSF repository'
    )
    collect_parser.add_argument(
        '--output', '-o',
        help='Output file to save collected IOCs'
    )
    collect_parser.add_argument(
        '--format',
        choices=['json', 'csv', 'txt'],
        default='json',
        help='Output format (default: json)'
    )

    # Recent command - Parse JSON files filtering for packages published in last 72h
    recent_parser = subparsers.add_parser(
        'recent',
        help='Parse JSON files filtering for packages published in last 72h'
    )
    recent_parser.add_argument(
        'folder_path',
        help='Path to folder containing JSON files to parse'
    )
    recent_parser.add_argument(
        '--hours',
        type=int,
        default=72,
        help='Lookback window in hours (default: 72)'
    )
    recent_parser.add_argument(
        '--output', '-o',
        help='Output file to save the filtered results (JSON format)'
    )

    # Clone OSSF malicious packages command
    clone_parser = subparsers.add_parser(
        'clone-ossf',
        help='Clone OSSF malicious packages repository and count JSON files'
    )
    clone_parser.add_argument(
        '--path',
        help='Local path to clone the repository (default: temp directory)'
    )
    
    # Parse malicious JSON files command
    parse_parser = subparsers.add_parser(
        'parse',
        help='Parse JSON files in a folder to extract affected packages'
    )
    parse_parser.add_argument(
        'folder_path',
        help='Path to folder containing JSON files to parse'
    )
    parse_parser.add_argument(
        '--output', '-o',
        help='Output file to save the parsed results (JSON format)'
    )
    
    return parser


def main() -> int:
    """Main entry point for the CLI tool."""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        if args.command == 'collect':
            collect_iocs(output=args.output)
        elif args.command == 'recent':
            # Handle recent command - parse with time filtering
            report = parse_recent_malicious_json_files(
                args.folder_path,
                hours=args.hours
            )
            
            if args.output:
                filtered_data = {
                    'filter_applied': f'{args.hours}_hours',
                    'total_files_processed': report.total_files_processed,
                    'total_packages_found': report.total_packages_found,
                    'recent_packages': [
                        pkg.to_dict() for pkg in report.packages
                    ],
                    'ecosystems': report.get_ecosystems()
                }
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(filtered_data, f, indent=2)
                print(f"Filtered results saved to {args.output}")
            else:
                if report.packages:
                    ecosystems = report.get_ecosystems()
                    print(f"Recent ecosystems: {', '.join(ecosystems)}")
                else:
                    print(f"No packages found within the last "
                          f"{args.hours} hours")
                    
        elif args.command == 'clone-ossf':
            clone_ossf_malicious_packages(local_path=args.path)
        elif args.command == 'parse':
            # Standard parsing without time filter
            report = parse_malicious_json_files(args.folder_path)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report.to_json())
                print(f"Results saved to {args.output}")
            else:
                print(report.to_json())
        else:
            parser.print_help()
            return 1

        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())