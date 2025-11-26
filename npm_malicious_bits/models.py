"""
Data models for NPM malicious bits processing.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
import json


@dataclass
class AffectedPackage:
    """Represents an affected package from malicious package data."""

    ecosystem: str
    published: Optional[str] = None
    package_name: str = ""
    versions: Optional[List[str]] = None

    def __str__(self) -> str:
        return f"{self.package_name} (published: {self.published})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            'ecosystem': self.ecosystem,
            'package_name': self.package_name,
            'published': self.published,
            'versions': ', '.join(self.versions) if self.versions else None
        }
        return result


@dataclass
class MaliciousPackageReport:
    """Represents a collection of affected packages from parsing JSON files."""

    packages: List[AffectedPackage]
    total_files_processed: int
    total_packages_found: int
 
    def __str__(self) -> str:
        return (f"MaliciousPackageReport: {self.total_packages_found} "
                f"packages from {self.total_files_processed} files")

    def get_ecosystems(self) -> List[str]:
        return list(set(pkg.ecosystem for pkg in self.packages))

    def get_packages_by_ecosystem(self, ecosystem: str) -> List[AffectedPackage]:  # noqa: E501
        return [pkg for pkg in self.packages if pkg.ecosystem == ecosystem]

    def get_ecosystem_statistics(self) -> Dict[str, int]:
        """Get statistics of package counts per ecosystem."""
        stats = {}
        for pkg in self.packages:
            if pkg.ecosystem in stats:
                stats[pkg.ecosystem] += 1
            else:
                stats[pkg.ecosystem] = 1
        return stats

    def display_ecosystem_statistics(self) -> str:
        """Display formatted statistics of packages per ecosystem."""
        stats = self.get_ecosystem_statistics()
        
        if not stats:
            return "No packages found"
        
        lines = ["Ecosystem Statistics:"]
        lines.append("=" * 20)
        
        # Sort by count (descending) then by name
        sorted_ecosystems = sorted(stats.items(),
                                   key=lambda x: (-x[1], x[0]))
        
        for ecosystem, count in sorted_ecosystems:
            percentage = (count / self.total_packages_found) * 100
            line = f"{ecosystem:12} : {count:4} packages ({percentage:5.1f}%)"
            lines.append(line)
        
        lines.append("-" * 20)
        lines.append(f"{'Total':12} : {self.total_packages_found:4} packages")
        
        return "\n".join(lines)

    def get_packages_within_hours(self, hours: int = 72
                                  ) -> List[AffectedPackage]:
        """
        Filter packages published within the specified number of hours.
        
        Args:
            hours: Number of hours to look back (default: 72)
            
        Returns:
            List of packages published within the specified timeframe
        """
        if hours <= 0:
            return []
            
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent_packages = []
        
        for pkg in self.packages:
            if pkg.published:
                try:

                    if pkg.published.endswith('Z'):
                        published_dt = datetime.fromisoformat(
                            pkg.published.replace('Z', '+00:00')
                        )
                    else:
                        published_dt = datetime.fromisoformat(pkg.published)
                    
                    if published_dt.tzinfo is None:
                        published_dt = published_dt.replace(
                            tzinfo=timezone.utc
                        )
                    
                    if published_dt >= cutoff_time:
                        recent_packages.append(pkg)
                        
                except (ValueError, TypeError) as e:
                    # Skip packages with invalid date formats
                    continue
        
        return recent_packages

    def to_json(self) -> str:
        return json.dumps({
            'total_files_processed': self.total_files_processed,
            'total_packages_found': self.total_packages_found,
            'ecosystems': self.get_ecosystems(),
            'ecosystem_statistics': self.get_ecosystem_statistics(),
            'packages': [pkg.to_dict() for pkg in self.packages]
        }, indent=2)