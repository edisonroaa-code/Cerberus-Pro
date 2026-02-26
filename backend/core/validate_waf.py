from core.waf_detective import fingerprint
from offensiva.evasion_strategies import get_bypass_strategies

print('waf_detective imported:', callable(fingerprint))
print('get_bypass_strategies example:', get_bypass_strategies('Cloudflare'))
