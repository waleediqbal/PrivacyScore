from collections import OrderedDict

from django.utils.translation import ugettext_lazy as _
from django.utils.translation import ungettext_lazy

from privacyscore.analysis.country_checks import describe_locations

# Checks are ordered in groups.
# Each check defines a set of keys it takes, the rating function
# and how to rate it (or not to rate it with None) when at least one key is
# missing.

CHECKS = {
    'privacy': OrderedDict(),
    'security': OrderedDict(),
    'ssl': OrderedDict(),
    'mx': OrderedDict(),
}

####################
## Privacy Checks ##
####################
# Check if OpenWPM died.
CHECKS['privacy']['openwpm_scan_failed'] = {
    'keys': {'third_parties_count'},
    'rating': lambda **keys: None,
    'missing': None
}

# Check for embedded third parties
# 0 parties: good
# else: bad
CHECKS['privacy']['third_parties'] = {
    'keys': {'third_parties_count', 'third_parties'},
    'rating': lambda **keys: {
        'description': _('The site does not use any third parties.'),
        'classification': 1
    } if keys['third_parties_count'] == 0 else {
        'description': _(''),
        'classification': 0
    },
    'missing': None
}
# Check for embedded known trackers
# 0 parties: good
# else: bad
CHECKS['privacy']['third_party-trackers'] = {
    'keys': {'tracker_requests',},
    'rating': lambda **keys: {
        'description': _('The site does not use any known tracking- or advertising companies.'),
        'classification': 1
    } if len(keys['tracker_requests']) == 0 else {
        'description': _(''),
        'classification': 0},
    'missing': None,
}
# Check for presence of first-party cookies
# 0 cookies: good
# else: good
CHECKS['privacy']['cookies_1st_party'] = {
    'keys': {'cookie_stats',},
    'rating': lambda **keys: {
        'description': _('The website itself is not setting any cookies.'),
        'classification': 1
    } if keys['cookie_stats']["first_party_short"] == 0 and keys['cookie_stats']["first_party_long"] == 0 else {
        'description': _(''),
        'classification': 1},
    'missing': None,
}

# Check for presence of third-party cookies
# 0 cookies: good
# else: bad
CHECKS['privacy']['cookies_3rd_party'] = {
    'keys': {'cookie_stats',},
    'rating': lambda **keys: {
        'description': _('No one else is setting any cookies.'),
        'classification': 1
    } if keys['cookie_stats']["third_party_short"] == 0 and keys['cookie_stats']["third_party_long"] == 0 else {
        'description': _(''),
        'classification':  0},
    'missing': None,
}
# Checks for presence of Google Analytics code
# No GA: good
# else: bad
CHECKS['privacy']['google_analytics_present'] = {
    'keys': {'google_analytics_present',},
    'rating': lambda **keys: {
        'description': _('The site uses Google Analytics.'),
        'classification': 0
    } if keys['google_analytics_present'] else {
        'description': _('The site does not use Google Analytics.'),
        'classification': 1
    },
    'missing': None,
}
# Check for AnonymizeIP setting on Google Analytics
# No GA: neutral
# AnonIP: good
# !AnonIP: bad
CHECKS['privacy']['google_analytics_anonymizeIP_not_set'] = {
    'keys': {'google_analytics_anonymizeIP_not_set', 'google_analytics_present'},
    'rating': lambda **keys: {
        'description': _('Not checking if Google Analytics data is being anonymized, as the site does not use Google Analytics.'),
        'classification': 1
    } if not keys["google_analytics_present"] else {
        'description': _('The site uses Google Analytics without the AnonymizeIP Privacy extension.'),
        'classification': 0
    } if keys['google_analytics_anonymizeIP_not_set'] else {
        'description': _('The site uses Google Analytics, however it instructs Google to store only anonymized IPs.'),
        'classification': 1
    },
    'missing': None,
}

# Check if web and mail servers are in the same country
# Servers in different countries: bad
# Else: good
CHECKS['privacy']['server_locations'] = {
    'keys': {'a_locations', 'mx_locations'},
    'rating': lambda **keys: {
        'description': _('The geo-location(s) of the web server(s) and the mail server(s) are not identical.'),
        'classification': 0
    } if (keys['a_locations'] and keys['mx_locations'] and
          set(keys['a_locations']) != set(keys['mx_locations'])) else {
        'description': _('The geo-location(s) of the web server(s) and the mail server(s) are identical.'),
        'classification': 1
    } if len(keys['mx_locations']) > 0 else {
        'description': _('Not checking if web and mail servers are in the same country, as there are no mail servers.'),
        'classification': 1
    },
    'missing': None,
}

#####################
## Security Checks ##
#####################

# Check for exposed internal system information
# No leaks: good
# Else: bad
CHECKS['security']['leaks'] = {
    'keys': {'leaks',},
    'rating': lambda **keys: {
        'description': _('The site does not disclose internal system information at usual paths.'),
        'classification': 1
    } if len(keys['leaks']) == 0 else {
        'description': _('The site discloses internal system information that should not be available.'),
        'classification':  0},
    'missing': None,
}
# Check for CSP header
# Present: good
# Not present: bad
CHECKS['security']['header_csp'] = {
    'keys': {'headerchecks',},
    'rating': lambda **keys: {
        'description': _('The site sets a Content-Security-Policy (CSP) header.'),
        'classification': 1
    } if keys['headerchecks'].get('content-security-policy') is not None and 
        keys['headerchecks']['content-security-policy']['status'] != "MISSING" else {
        'description': _('The site does not set a Content-Security-Policy (CSP) header.'),
        'classification':  0},
    'missing': None,
}
# Check for XFO header
# Present: good
# Not present: bad
CHECKS['security']['header_xfo'] = {
    'keys': {'headerchecks',},
    'rating': lambda **keys: {
        'description': _('The site sets a X-Frame-Options (XFO) header.'),
        'classification': 1
    } if keys['headerchecks'].get('x-frame-options') is not None and
        keys['headerchecks']['x-frame-options']['status'] != "MISSING" else {
        'description': _('The site does not set a X-Frame-Options (XFO) header.'),
        'classification':  0},
    'missing': None,
}
# Check for X-XSS-Protection header
# Present: good
# Not present: bad
CHECKS['security']['header_xssp'] = {
    'keys': {'headerchecks',},
    'rating': lambda **keys: {
        'description': _('The site sets a X-XSS-Protection  header.'),
        'classification': 1
    } if keys['headerchecks'].get('x-xss-protection') is not None and 
    keys['headerchecks']['x-xss-protection']['status'] != "MISSING" else {
        'description': _('The site does not set a X-XSS-Protection header.'),
        'classification':  0},
    'missing': None,
}
# Check for XCTO header
# Present: good
# Not present: bad
CHECKS['security']['header_xcto'] = {
    'keys': {'headerchecks',},
    'rating': lambda **keys: {
        'description': _('The site sets a X-Content-Type-Options header.'),
        'classification': 1
    } if keys['headerchecks'].get('x-content-type-options') is not None and 
        keys['headerchecks']['x-content-type-options']['status'] != "MISSING" else {
        'description': _('The site does not set a X-Content-Type-Options header.'),
        'classification':  0},
    'missing': None,
}

# Check for Referrer policy header
# Present: good
# Not present: bad
CHECKS['security']['header_ref'] = {
    'keys': {'headerchecks',},
    'rating': lambda **keys: {
        'description': _('The site sets a Referrer-Policy header.'),
        'classification': 1
    } if keys['headerchecks'].get('referrer-policy') is not None and 
        keys['headerchecks']['referrer-policy']['status'] != "MISSING" else {
        'description': _('The site does not set a referrer-policy header.'),
        'classification':  0},
    'missing': None,
}


##########################
## Webserver SSL Checks ##
##########################

# Check if server scan timed out
# no: Nothing
# yes: notify, neutral
CHECKS['ssl']['https_scan_finished'] = {
    'keys': {'web_ssl_finished', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The website does not offer an encrypted (HTTPS) version.'),
        'classification': 0
    } if keys['web_ssl_finished'] and not keys['web_has_ssl'] else None,
    'missing': None
}
# Check if website does not redirect to HTTPS, but offers HTTPS on demand and serves the same content
# HTTPS available and serving same content: good
# HTTPS available but different content: bad
# We only scanned the HTTPS version: neutral (does not influence rating)
CHECKS['ssl']['no_https_by_default_but_same_content_via_https'] = {
    'keys': {'final_url','final_https_url','same_content_via_https'},
    'rating': lambda **keys: {
        'description': _('The site does not use HTTPS by default but it makes available the same content via HTTPS upon request.'),
        'classification': 1,
    } if (not keys['final_url'].startswith('https') and 
          keys['final_https_url'] and
          keys['final_https_url'].startswith('https') and
          keys['same_content_via_https']) else {
        'description': _('The web server does not support HTTPS by default. It hosts an HTTPS site, but it does not serve the same content over HTTPS that is offered via HTTP.'),
        'classification': 0,
    } if (not keys['final_url'].startswith('https') and
          keys['final_https_url'] and
          keys['final_https_url'].startswith('https') and
          not keys['same_content_via_https']) else {
        'description': _('Not comparing between HTTP and HTTPS version, as the website was scanned only over HTTPS.'),
        'classification': 0,
    } if (keys["final_url"].startswith("https:")) else None,
    'missing': None,
}
# Check if server cert is valid
# yes: good
# no: bad
CHECKS['ssl']['web_cert'] = {
    'keys': {'web_has_ssl', 'web_cert_trusted', 'web_cert_trusted_reason'},
    'rating': lambda **keys: {
        'description': _('The website uses a valid security certificate.'),
        'classification': 1,
    } if keys['web_has_ssl'] and keys['web_cert_trusted'] else {
        'description': _('Not checking SSL certificate, as the server does not offer SSL'),
        'classification': 0,
    } if not keys['web_has_ssl'] else {
        'description': _('Server uses an invalid SSL certificate.'),
        'classification': 0,
    },
    'missing': None
}
# Check if server forwarded us to HTTPS version
# yes: good
# no: neutral (as it may still happen, we're not yet explicitly checking the HTTP version)
# TODO Explicitly check http://-version and see if we are being forwarded, even if user provided https://-version
CHECKS['ssl']['site_redirects_to_https'] = {
    'keys': {'redirected_to_https', 'https', 'final_https_url', 'web_has_ssl', 'web_cert_trusted', 'initial_url'},
    'rating': lambda **keys: {
        'description': _('The website redirects visitors to the secure (HTTPS) version.'),
        'classification': 1,
    } if keys['redirected_to_https'] else {
        'description': _('Not checking if websites automatically redirects to HTTPS version, as the provided URL already was HTTPS.'),
        'classification': 0,
    } if keys["initial_url"].startswith('https') else {
        'description': _('The website does not redirect visitors to the secure (HTTPS) version, even though one is available.'),
        'classification': 0,
    } if not keys['redirected_to_https'] and keys["web_has_ssl"] and keys['web_cert_trusted'] else {
        'description': _('Not testing for forward to HTTPS, as the webserver does not offer a well-configured HTTPS.'),
        'classification': 0,
    },
    'missing': None,
}
# Check if website explicitly redirected us from HTTPS to the HTTP version
# yes: bad
# no: good
CHECKS['ssl']['redirects_from_https_to_http'] = {
    'keys': {'final_https_url', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The web server redirects to HTTP if content is requested via HTTPS.'),
        'classification': 0,
    } if (keys['final_https_url'] and keys['final_https_url'].startswith('http:')) else {
        'description': _('Not checking for HTTPS->HTTP redirection, as the server does not offer HTTPS.'),
        'classification': 0,
    } if not keys['web_has_ssl'] else {
        'description': _('The web server does not redirect to HTTP if content is requested via HTTPS'),
        'classification': 1,
    },
    'missing': None,
}
# Check for Perfect Forward Secrecy on Webserver
# PFS available: good
# Else: bad
CHECKS['ssl']['web_pfs'] = {
    'keys': {'web_pfs',},
    'rating': lambda **keys: {
        'description': _('The web server is supporting perfect forward secrecy.'),
        'classification': 1,
    } if keys['web_pfs'] else {
        'description': _('The web server is not supporting perfect forward secrecy.'),
        'classification': 0,
    },
    'missing': None,
}
# Checks for HSTS Preload header
# HSTS present: good
# No HSTS: bad
# No HTTPS at all: Neutral
CHECKS['ssl']['web_hsts_header'] = {
    'keys': {'web_has_hsts_preload_header', 'web_has_hsts_header', 'web_has_hsts_preload', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _("Not checking for HSTS support, as the server does not offer HTTPS."),
        'classification': 0,
    } if not keys['web_has_ssl'] else {
        'description': _('The server uses HSTS to prevent insecure requests.'),
        'classification': 1,
    } if keys['web_has_hsts_header'] or keys['web_has_hsts_preload'] else {
        'description': _('The site is not using HSTS to prevent insecure requests.'),
        'classification': 0,
    },
    'missing': None,
}
# Checks for HSTS Preload header duration
# HSTS duration good: good
# Too short: bad
# No HTTPS at all: Neutral
CHECKS['ssl']['web_hsts_header_duration'] = {
    'keys': {'web_has_hsts_preload_header', 'web_has_hsts_header', 'web_has_hsts_header_sufficient_time', 'web_has_ssl'},
    'rating': lambda **keys: None if not keys['web_has_ssl'] else {
        'description': _('The server is not using HSTS, so not checking HSTS validity duration.'),
        'classification': 0,
    } if not (keys['web_has_hsts_header'] or keys['web_has_hsts_preload']) else {
        'description': _('The site uses HSTS with a sufficiently long duration.'),
        'classification': 1,
    } if keys['web_has_hsts_header_sufficient_time'] else {
        'description': _('The validity of the HSTS header is too short.'),
        'classification': 0,
    },
    'missing': None,
}
# Checks for HSTS preloading preparations
# HSTS preloading prepared or already done: good
# No HSTS preloading: bad
# No HSTS / HTTPS: neutral
CHECKS['ssl']['web_hsts_preload_prepared'] = {
    'keys': {'web_has_hsts_preload_header', 'web_has_hsts_header', 'web_has_hsts_preload', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _("Not checking for HSTS Preloading support, as the server does not offer HTTPS."),
        'classification': 0,
    } if not keys['web_has_ssl'] else {
        'description': _('The server is ready for HSTS preloading.'),
        'classification': 1,
    } if keys['web_has_hsts_preload'] or keys['web_has_hsts_preload_header'] else {
        'description': _('The site is not using HSTS preloading to prevent insecure requests.'),
        'classification': 0,
    } if keys['web_has_hsts_header'] else {
        'description': _('Not checking for HSTS preloading, as the website does not offer HSTS.'),
        'classification': 0
    },
    'missing': None,
}
# Checks for HSTS preloading in list
# HSTS preloaded: good
# Not in database: bad
# No HSTS / HTTPS: neutral
CHECKS['ssl']['web_hsts_preload_listed'] = {
    'keys': {'web_has_hsts_preload_header', 'web_has_hsts_header', 'web_has_hsts_preload', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _("Not checking for HSTS Preloading list inclusion, as the server does not offer HTTPS."),
        'classification': 0,
    } if not keys['web_has_ssl'] else {
        'description': _('The server is part of the Chrome HSTS preload list.'),
        'classification': 1,
    } if keys['web_has_hsts_preload'] else {
        'description': _('The server is ready for HSTS preloading, but not in the preloading database yet.'),
        'classification': 0
    } if keys['web_has_hsts_preload_header'] else {
        'description': _('Not checking for inclusion in HSTS preloading lists, as the website does not advertise it.'),
        'classification': 0,
    } if keys['web_has_hsts_header'] else {
        'description': _('Not checking for inclusion in HSTS preloading lists, as the website does not offer HSTS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for HTTP Public Key Pinning Header
# HPKP present: Good, but does not influence ranking
# No HTTPS: Neutral
# else: bad, but does not influence ranking
CHECKS['ssl']['web_has_hpkp_header'] = {
    'keys': {'web_has_hpkp_header', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The site uses Public Key Pinning to prevent attackers from using invalid certificates.'),
        'classification': 1,
    } if keys['web_has_hpkp_header'] else {
        'description': _('The site is not using Public Key Pinning to prevent attackers from using invalid certificates.'),
        'classification': 0,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for HPKP support, as the server does not offer HTTPS.'),
        'classification': 0,
    },
    'missing': None,
}
# Check for insecure SSLv2 protocol
# No SSLv2: Good
# No HTTPS at all: neutral
# Else: bad
CHECKS['ssl']['web_insecure_protocols_sslv2'] = {
    'keys': {'web_has_protocol_sslv2', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server does not support SSLv2.'),
        'classification': 1,
    } if not keys["web_has_protocol_sslv2"] else {
        'description': _('The server supports SSLv2.'),
        'classification': 0,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for SSLv2 support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None
}
# Check for insecure SSLv3 protocol
# No SSLv3: Good
# Not HTTPS at all: neutral
# Else: bad
CHECKS['ssl']['web_insecure_protocols_sslv3'] = {
    'keys': {'web_has_protocol_sslv3', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server does not support SSLv3.'),
        'classification': 1,
    } if not keys["web_has_protocol_sslv3"] else {
        'description': _('The server supports SSLv3.'),
        'classification': 0,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for SSLv3 support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for TLS 1.0
# supported: neutral
# Else: good
CHECKS['ssl']['web_secure_protocols_tls1'] = {
    'keys': {'web_has_protocol_tls1', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server supports TLS 1.0.'),
        'classification': 0,
    } if keys["web_has_protocol_tls1"] else {
        'description': _('The server does not support TLS 1.0.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for TLS 1.0-support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for TLS 1.1
# supported: neutral
# Else: neutral
CHECKS['ssl']['web_secure_protocols_tls1_1'] = {
    'keys': {'web_has_protocol_tls1_1', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server supports TLS 1.1.'),
        'classification': 0,
    } if keys["web_has_protocol_tls1_1"] else {
        'description': _('The server does not support TLS 1.1.'),
        'classification': 0,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for TLS 1.1-support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing':None,
}
# Check for TLS 1.2
# supported: good
# Else: critical
CHECKS['ssl']['web_secure_protocols_tls1_2'] = {
    'keys': {'web_has_protocol_tls1_2', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server supports TLS 1.2.'),
        'classification': 1,
    } if keys["web_has_protocol_tls1_2"] else {
        'description': _('The server does not support TLS 1.2.'),
        'classification': 0,
    }if keys['web_has_ssl'] else {
        'description': _('Not checking for TLS 1.2-support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for mixed content
# No mixed content: Good
# Else: bad
CHECKS['ssl']['mixed_content'] = {
    'keys': {'final_url','mixed_content'},
    'rating': lambda **keys: {
        'description': _('The site uses HTTPS, but some objects are retrieved via HTTP (mixed content).'),
        'classification': 0
    } if (keys['mixed_content'] and keys['final_url'].startswith('https')) else {
        'description': _('The site uses HTTPS and all objects are retrieved via HTTPS (no mixed content).'),
        'classification': 1
    } if (not keys['mixed_content'] and keys['final_url'].startswith('https')) else {
        'description': _('The site was scanned via HTTP only, mixed content checks do not apply.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Heartbleed
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_heartbleed'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the Heartbleed attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('heartbleed')['finding']
    } if keys["web_vulnerabilities"].get('heartbleed') else {
        'description': _('The server is secure against the Heartbleed attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the Heartbleed vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for CCS
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_ccs'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the CCS attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('ccs')['finding']
    } if keys["web_vulnerabilities"].get('ccs') else {
        'description': _('The server is secure against the CCS attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the CCS vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for ticketbleed
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_ticketbleed'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the Ticketbleed attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('ticketbleed')['finding']
    } if keys["web_vulnerabilities"].get('ticketbleed') else {
        'description': _('The server is secure against the Ticketbleed attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the Ticketbleed vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Secure Renegotiation
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_secure_renego'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to a Secure Re-Negotiation attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('secure-renego')['finding']
    } if keys["web_vulnerabilities"].get('secure-renego') else {
        'description': _('The server is secure against the Secure Re-Negotiation attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the Secure Re-Negotiation vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Secure Client Renego
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_secure_client_renego'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the Secure Client Re-Negotiation attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('sec_client_renego')['finding']
    } if keys["web_vulnerabilities"].get('sec_client_renego') else {
        'description': _('The server is secure against the Secure Client Re-Negotiation attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the Secure Client Re-Negotiation vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for CRIME
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_crime'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the CRIME attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('crime')['finding']
    } if keys["web_vulnerabilities"].get('crime') else {
        'description': _('The server is secure against the CRIME attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the CRIME vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for BREACH
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_breach'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the BREACH attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('breach')['finding']
    } if keys["web_vulnerabilities"].get('breach') else {
        'description': _('The server is secure against the BREACH attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the BREACH vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for POODLE
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_poodle'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the POODLE attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('poodle_ssl')['finding']
    } if keys["web_vulnerabilities"].get('poodle_ssl') else {
        'description': _('The server is secure against the POODLE attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the POODLE vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Sweet32
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_sweet32'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the SWEET32 attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('sweet32')['finding']
    } if keys["web_vulnerabilities"].get('sweet32') else {
        'description': _('The server is secure against the SWEET32 attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the SWEET32 vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for FREAK
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_freak'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the FREAK attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('freak')['finding']
    } if keys["web_vulnerabilities"].get('freak') else {
        'description': _('The server is secure against the FREAK attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the FREAK vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for DROWN
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_drown'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the DROWN attack.'),
        'classification': 0
    } if keys["web_vulnerabilities"].get('drown') else {
        'description': _('The server is secure against the DROWN attack.'),
        'classification': 1
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the DROWN vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for LogJam
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_logjam'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the LOGJAM attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('logjam')['finding']
    } if keys["web_vulnerabilities"].get('logjam') else {
        'description': _('The server is secure against the LOGJAM attack.'),
        'classification': 1
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the LOGJAM vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for BEAST
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_beast'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the BEAST attack.'),
        'classification': 0,
        'finding': keys["web_vulnerabilities"].get('beast')['finding']
    } if keys["web_vulnerabilities"].get('beast') else {
        'description': _('The server is secure against the BEAST attack.'),
        'classification': 1,
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the BEAST vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Lucky13
# vulnerable: bad
# Else: good
CHECKS['ssl']['web_vuln_lucky13'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the LUCKY13 attack.'),
        'classification': 0
    } if keys["web_vulnerabilities"].get('lucky13') else {
        'description': _('The server is secure against the LUCKY13 attack.'),
        'classification': 1
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for the LUCKY13 vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for RC4
# Supported: bad
# Else: good
CHECKS['ssl']['web_vuln_rc4'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server supports the outdated and insecure RC4 cipher.'),
        'classification': 0
    } if keys["web_vulnerabilities"].get('rc4') else {
        'description': _('The server does not support the outdated and insecure RC4 cipher.'),
        'classification': 1
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for RC4 cipher support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Fallback_SCSV support
# not supported: bad
# Else: good
CHECKS['ssl']['web_vuln_fallback_scsv'] = {
    'keys': {'web_vulnerabilities', 'web_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server is not using TLS_FALLBACK_SCSV to prevent downgrade attacks.'),
        'classification': 0
    } if keys["web_vulnerabilities"].get('fallback_scsv') else {
        'description': _('The server uses TLS_FALLBACK_SCSV to prevent downgrade attacks.'),
        'classification': 1
    } if keys['web_has_ssl'] else {
        'description': _('Not checking for TLS_FALLBACK_SCSV support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}

###########################
## Mailserver TLS Checks ##
###########################
# Check if mail server exists at all
# No mailserver: Good
# Else: None
CHECKS['mx']['has_mx'] = {
    'keys': {'mx_records'},
    'rating': lambda **keys: {
        'description': _('No mail server is available for this site.'),
        'classification': 1,
    } if not keys['mx_records'] else None,
    'missing': None,
}
# Check if mail server check actually finished
# Result is informational
CHECKS['mx']['mx_scan_finished'] = {
    'keys': {'mx_ssl_finished', 'mx_has_ssl', 'mx_records'},
    'rating': lambda **keys: {
        'description': _('The mail server does not seem to support encryption.'),
        'classification': 0,
    } if keys['mx_ssl_finished'] and not keys['mx_has_ssl'] and len(keys['mx_records']) > 0 else None,
    'missing': None,
}
# Check for insecure SSLv2 protocol
# No SSLv2: Good
# No HTTPS at all: neutral
# Else: bad
CHECKS['mx']['mx_insecure_protocols_sslv2'] = {
    'keys': {'mx_has_protocol_sslv2', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server does not support SSLv2.'),
        'classification': 1,
    } if not keys['mx_has_protocol_sslv2'] else {
        'description': _('The server supports SSLv2.'),
        'classification': 0,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for SSLv2 support, as the server does not offer TLS.'),
        'classification': 0
    },
    'missing': None
}
# Check for insecure SSLv3 protocol
# No SSLv3: Good
# Not HTTPS at all: neutral
# Else: bad
CHECKS['mx']['mx_insecure_protocols_sslv3'] = {
    'keys': {'mx_has_protocol_sslv3', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server does not support SSLv3.'),
        'classification': 1,
    } if not keys["mx_has_protocol_sslv3"] else {
        'description': _('The server supports SSLv3.'),
        'classification': 0,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for SSLv3 support, as the server does not offer TLS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for TLS 1.0
# supported: neutral
# Else: good
CHECKS['mx']['mx_secure_protocols_tls1'] = {
    'keys': {'mx_has_protocol_tls1', "mx_has_ssl"},
    'rating': lambda **keys: {
        'description': _('The server supports TLS 1.0.'),
        'classification': 0,
    } if keys['mx_has_protocol_tls1'] else {
        'description': _('The server does not support TLS 1.0.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for TLS 1.0-support, as the server does not offer TLS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for TLS 1.1
# supported: neutral
# Else: neutral
CHECKS['mx']['mx_secure_protocols_tls1_1'] = {
    'keys': {'mx_has_protocol_tls1_1', "mx_has_ssl"},
    'rating': lambda **keys: {
        'description': _('The server supports TLS 1.1.'),
        'classification': 0,
    } if keys['mx_has_protocol_tls1_1'] else {
        'description': _('The server does not support TLS 1.1.'),
        'classification': 0,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for TLS 1.1-support, as the server does not offer TLS.'),
        'classification': 0
    },
    'missing':None,
}
# Check for TLS 1.2
# supported: good
# Else: critical
CHECKS['mx']['mx_secure_protocols_tls1_2'] = {
    'keys': {'mx_has_protocol_tls1_2', "mx_has_ssl"},
    'rating': lambda **keys: {
        'description': _('The server supports TLS 1.2.'),
        'classification': 1
    } if keys['mx_has_protocol_tls1_2'] else {
        'description': _('The server does not support TLS 1.2.'),
        'classification': 0
    }if keys['mx_has_ssl'] else {
        'description': _('Not checking for TLS 1.2-support, as the server does not offer TLS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Heartbleed
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_heartbleed'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the Heartbleed attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('heartbleed')['finding']
    } if keys["mx_vulnerabilities"].get('heartbleed') else {
        'description': _('The server is secure against the Heartbleed attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the Heartbleed vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for CCS
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_ccs'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the CCS attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('ccs')['finding']
    } if keys["mx_vulnerabilities"].get('ccs') else {
        'description': _('The server is secure against the CCS attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the CCS vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for ticketbleed
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_ticketbleed'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the Ticketbleed attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('ticketbleed')['finding']
    } if keys["mx_vulnerabilities"].get('ticketbleed') else {
        'description': _('The server is secure against the Ticketbleed attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the Ticketbleed vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Secure Renegotiation
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_secure_renego'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to a Secure Re-Negotiation attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('secure-renego')['finding']
    } if keys["mx_vulnerabilities"].get('secure-renego') else {
        'description': _('The server is secure against the Secure Re-Negotiation attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the Secure Re-Negotiation vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Secure Client Renego
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_secure_client_renego'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the Secure Client Re-Negotiation attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('sec_client_renego')['finding']
    } if keys["mx_vulnerabilities"].get('sec_client_renego') else {
        'description': _('The server is secure against the Secure Client Re-Negotiation attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the Secure Client Re-Negotiation vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for CRIME
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_crime'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the CRIME attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('crime')['finding']
    } if keys["mx_vulnerabilities"].get('crime') else {
        'description': _('The server is secure against the CRIME attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the CRIME vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for BREACH
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_breach'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the BREACH attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('breach')['finding']
    } if keys["mx_vulnerabilities"].get('breach') else {
        'description': _('The server is secure against the BREACH attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the BREACH vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for POODLE
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_poodle'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the POODLE attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('poodle_ssl')['finding']
    } if keys["mx_vulnerabilities"].get('poodle_ssl') else {
        'description': _('The server is secure against the POODLE attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the POODLE vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Sweet32
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_sweet32'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the SWEET32 attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('sweet32')['finding']
    } if keys["mx_vulnerabilities"].get('sweet32') else {
        'description': _('The server is secure against the SWEET32 attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the SWEET32 vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for FREAK
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_freak'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the FREAK attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('freak')['finding']
    } if keys["mx_vulnerabilities"].get('freak') else {
        'description': _('The server is secure against the FREAK attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the FREAK vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for DROWN
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_drown'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the DROWN attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('drown')['finding']
    } if keys["mx_vulnerabilities"].get('drown') else {
        'description': _('The server is secure against the DROWN attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the DROWN vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for LogJam
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_logjam'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the LOGJAM attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('logjam')['finding']
    } if keys["mx_vulnerabilities"].get('logjam') else {
        'description': _('The server is secure against the LOGJAM attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the LOGJAM vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for BEAST
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_beast'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the BEAST attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('beast')['finding']
    } if keys["mx_vulnerabilities"].get('beast') else {
        'description': _('The server is secure against the BEAST attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the BEAST vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Lucky13
# vulnerable: bad
# Else: good
CHECKS['mx']['mx_vuln_lucky13'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server may be vulnerable to the LUCKY13 attack.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('lucky13')['finding']
    } if keys["mx_vulnerabilities"].get('lucky13') else {
        'description': _('The server is secure against the LUCKY13 attack.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for the LUCKY13 vulnerability, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for RC4
# Supported: bad
# Else: good
CHECKS['mx']['mx_vuln_rc4'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server supports the outdated and insecure RC4 cipher.'),
        'classification': 0,
        'finding': keys["mx_vulnerabilities"].get('rc4')['finding']
    } if keys["mx_vulnerabilities"].get('rc4') else {
        'description': _('The server does not support the outdated and insecure RC4 cipher.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for RC4 cipher support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}
# Check for Fallback_SCSV support
# not supported: bad
# Else: good
CHECKS['mx']['mx_vuln_fallback_scsv'] = {
    'keys': {'mx_vulnerabilities', 'mx_has_ssl'},
    'rating': lambda **keys: {
        'description': _('The server is not using TLS_FALLBACK_SCSV to prevent downgrade attacks.'),
        'classification': 0,
    } if keys["mx_vulnerabilities"].get('fallback_scsv') else {
        'description': _('The server uses TLS_FALLBACK_SCSV to prevent downgrade attacks.'),
        'classification': 1,
    } if keys['mx_has_ssl'] else {
        'description': _('Not checking for TLS_FALLBACK_SCSV support, as the server does not offer HTTPS.'),
        'classification': 0
    },
    'missing': None,
}

# Add textual descriptions and labels and stuff
CHECKS['privacy']['openwpm_scan_failed']['title'] = "Check if Website scan succeeded"

CHECKS['privacy']['third_parties']['title'] = "Check if 3rd party embeds are being used"

CHECKS['privacy']['third_party-trackers']['title'] = 'Check if embedded 3rd parties are known trackers'

CHECKS['privacy']['cookies_1st_party']['title'] = "Determine how many cookies the website sets"

CHECKS['privacy']['cookies_3rd_party']['title'] = "Determine how many cookies are set by third parties"

CHECKS['privacy']['google_analytics_present']['title'] = 'Check if Google Analytics is being used'

CHECKS['privacy']['google_analytics_anonymizeIP_not_set']['title'] = "Check if Google Analytics has the privacy extension enabled"

CHECKS['privacy']['server_locations']['title'] = 'Check whether web & mail servers are located in same country'

CHECKS['security']['leaks']['title'] = "Check for unintentional information leaks"

CHECKS['security']['header_xfo']['title'] = 'Check for presence of X-Frame-Options'

CHECKS['security']['header_xssp']['title'] = "Check for secure XSS Protection"

CHECKS['security']['header_xcto']['title'] = "Check for secure X-Content-Type-Options"

CHECKS['security']['header_ref']['title'] = "Check for privacy-friendly Referrer Policy"

CHECKS['ssl']['https_scan_finished']['title'] = "Check if the Server offers HTTPS"

CHECKS['ssl']['no_https_by_default_but_same_content_via_https']['title'] = 'Check whether HTTP URL is also reachable via HTTPS'

CHECKS['ssl']['web_cert']['title'] = "Check whether the SSL certificate is valid"

CHECKS['ssl']['site_redirects_to_https']['title'] = "Check for automatic redirection to HTTPS"

CHECKS['ssl']['redirects_from_https_to_http']['title'] = "Check if the server prevents from using HTTPS version of website"

CHECKS['ssl']['web_pfs']['title'] = "Check if the server offers Perfect Forward Secrecy"

CHECKS['ssl']['web_hsts_header']['title'] = "Check for valid Strict-Transport-Security (HSTS)"

CHECKS['ssl']['web_hsts_header_duration']['title'] = "Check for duration given in HSTS header"

CHECKS['ssl']['web_hsts_preload_prepared']['title'] = "Check if server is ready for HSTS preloading"

CHECKS['ssl']['web_hsts_preload_listed']['title'] = "Check for HSTS Preloading"

CHECKS['ssl']['web_has_hpkp_header']['title'] = 'Check for valid Public Key Pins'

CHECKS['ssl']['mixed_content']['title'] = "Check for Mixed Content on HTTPS sites"

CHECKS['ssl']['web_insecure_protocols_sslv2']['title'] = \
CHECKS['mx']['mx_insecure_protocols_sslv2']['title'] = "Check that insecure SSL 2.0 is not offered"

CHECKS['ssl']['web_insecure_protocols_sslv3']['title'] = \
CHECKS['mx']['mx_insecure_protocols_sslv3']['title'] = "Check that insecure SSL 3.0 is not offered"

CHECKS['ssl']['web_secure_protocols_tls1']['title'] = \
CHECKS['mx']['mx_secure_protocols_tls1']['title'] = "Check if legacy TLS 1.0 is offered"

CHECKS['ssl']['web_secure_protocols_tls1_1']['title'] = \
CHECKS['mx']['mx_secure_protocols_tls1_1']['title'] = "Check if TLS 1.1 is offered "

CHECKS['ssl']['web_secure_protocols_tls1_2']['title'] = \
CHECKS['mx']['mx_secure_protocols_tls1_2']['title'] = "Check that TLS 1.2 is offered"

CHECKS['ssl']['web_vuln_heartbleed']['title'] = \
CHECKS['mx']['mx_vuln_heartbleed']['title'] = 'Check for protection against Heartbleed'

CHECKS['ssl']['web_vuln_ccs']['title'] = \
CHECKS['mx']['mx_vuln_ccs']['title'] = "Check for protection against CCS attack"

CHECKS['ssl']['web_vuln_ticketbleed']['title'] = \
CHECKS['mx']['mx_vuln_ticketbleed']['title'] = "Check for protection against Ticketbleed"

CHECKS['ssl']['web_vuln_secure_renego']['title'] = \
CHECKS['mx']['mx_vuln_secure_renego']['title'] = "Check for Secure Renegotiation"

CHECKS['ssl']['web_vuln_secure_client_renego']['title'] = \
CHECKS['mx']['mx_vuln_secure_client_renego']['title'] = "Check for Secure Client-Initiated Renegotiation"

CHECKS['ssl']['web_vuln_crime']['title'] = \
CHECKS['mx']['mx_vuln_crime']['title'] = "Check for protection against CRIME"

CHECKS['ssl']['web_vuln_breach']['title'] = \
CHECKS['mx']['mx_vuln_breach']['title'] = "Check for protection against BREACH"

CHECKS['ssl']['web_vuln_poodle']['title'] = \
CHECKS['mx']['mx_vuln_poodle']['title'] = "Check for protection against POODLE"

CHECKS['ssl']['web_vuln_sweet32']['title'] = \
CHECKS['mx']['mx_vuln_sweet32']['title'] = "Check for protection against SWEET32"

CHECKS['ssl']['web_vuln_freak']['title'] = \
CHECKS['mx']['mx_vuln_freak']['title'] = "Check for protection against FREAK"

CHECKS['ssl']['web_vuln_drown']['title'] = \
CHECKS['mx']['mx_vuln_drown']['title'] = "Check for protection against DROWN"

CHECKS['ssl']['web_vuln_logjam']['title'] = \
CHECKS['mx']['mx_vuln_logjam']['title'] = "Check for protection against LOGJAM"

CHECKS['ssl']['web_vuln_beast']['title'] = \
CHECKS['mx']['mx_vuln_beast']['title'] = "Check for protection against BEAST"

CHECKS['ssl']['web_vuln_lucky13']['title'] = \
CHECKS['mx']['mx_vuln_lucky13']['title'] = "Check for protection against LUCKY13"

CHECKS['ssl']['web_vuln_rc4']['title'] = \
CHECKS['mx']['mx_vuln_rc4']['title'] = "Check that no RC4 ciphers are used"

CHECKS['ssl']['web_vuln_fallback_scsv']['title'] = \
CHECKS['mx']['mx_vuln_fallback_scsv']['title'] = "Check that TLS_FALLBACK_SCSV is implemented"

CHECKS['mx']['has_mx']['title'] = "Check if the Domain has an eMail server"

CHECKS['mx']['mx_scan_finished']['title'] = "Check if the Mail server supports encryption"
