import random
from typing import Dict, List, Tuple

class HeaderScrubber:
    """
    Utilities to evade WAF detection by scrubbing identifiable information
    and mimicking legitimate browser traffic.
    """
    
    # Common legitimate User-Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    ]
    
    # Common noise headers to mimic real browser requests
    NOISE_HEADERS = [
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Cache-Control", "max-age=0")
    ]

    @staticmethod
    def get_random_user_agent() -> str:
        """Return a random legitimate User-Agent"""
        return random.choice(HeaderScrubber.USER_AGENTS)

    @staticmethod
    def get_clean_headers(extra_headers: Dict[str, str] = None) -> List[str]:
        """
        Generate a list of formatted headers for sqlmap that mimic a real browser.
        """
        headers = []
        
        # Add random Noise headers (pick 3-5 random ones plus mandatory ones)
        selected_noise = random.sample(HeaderScrubber.NOISE_HEADERS, k=random.randint(3, 5))
        
        # Always include Accept and Accept-Language if not present
        has_accept = any(h[0] == "Accept" for h in selected_noise)
        if not has_accept:
             headers.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
             
        for key, value in selected_noise:
            headers.append(f"{key}: {value}")
            
        # Add extra custom headers
        if extra_headers:
            for k, v in extra_headers.items():
                headers.append(f"{k}: {v}")
                
        return headers

    @staticmethod
    def get_sqlmap_arguments() -> List[str]:
        """
        Return arguments to force sqlmap to be stealthy.
        """
        ua = HeaderScrubber.get_random_user_agent()
        
        header_list = HeaderScrubber.get_clean_headers()
        # Use actual newline character for sqlmap headers
        header_str = "\n".join(header_list)
        
        args = [
            f"--user-agent={ua}",
            f"--headers={header_str}",
            "--random-agent"
        ]
        
        # Occasional mobile emulation (added only if active)
        if random.random() < 0.1:
            args.append("--mobile")
            
        return args
