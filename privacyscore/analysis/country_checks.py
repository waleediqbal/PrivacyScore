from django.utils.translation import ugettext_lazy as _

EU_STATES = [
    'Austria',
    'Belgium',
    'Bulgaria',
    'Croatia',
    'Cyprus',
    'Czech Republic',
    'Denmark',
    'Estonia',
    'Europe', # This is actually very much debatable (Europe != EU), but EU organizations tend to be located in this "country". We don't want to punish them for that.
    'Finland',
    'France',
    'Germany',
    'Greece',
    'Hungary',
    'Ireland',
    'Italy',
    'Latvia',
    'Lithuania',
    'Luxembourg',
    'Malta',
    'Netherlands',
    'Poland',
    'Portugal',
    'Romania',
    'Slovakia',
    'Slovenia',
    'Spain',
    'Sweden',
    'United Kingdom',
]


def describe_locations(server_type: str, locations: list) -> dict:
    """Describe a list of locations."""
    locations = [location for location in locations if location]
    if not locations:
        return {
            'description': _('The locations of the %(server_type)s could not '
                             'be detected.') % {'server_type': server_type},
            'classification': 0
        }
    category = 1
    for country in locations:
        if country not in EU_STATES:
            category = 0
    if len(locations) == 1:
        return {
            'description': _(''), 
            'classification': category
        }
    return {
        'description': _(''),
        'classification': category
    }
