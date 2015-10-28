import argparse
import re

from oauth2client import client
import oauth2client.file
import oauth2client.tools
import gdata.gauth
import gdata.contacts.client


#SCOPE = "https://www.googleapis.com/auth/contacts.readonly"
SCOPE = "https://www.google.com/m8/feeds"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
MAX_RESULTS = 2000


def authenticate():
    storage = oauth2client.file.Storage('creds.data')
    credentials = storage.get()
    if credentials is not None:
        return credentials
    flow = client.flow_from_clientsecrets(
        'client_secret.json',
        scope=SCOPE,
        redirect_uri=REDIRECT_URI)
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     parents=[oauth2client.tools.argparser])
    flags = parser.parse_args()
    # Replaced with "run_flow" below
    #auth_uri = flow.step1_get_authorize_url()
    #webbrowser.open(auth_uri)
    #auth_code = raw_input('Enter the auth code: ')
    #credentials = flow.step2_exchange(auth_code)
    credentials = oauth2client.tools.run_flow(flow, storage, flags)
    return credentials


def get_all_contacts(gd_client):
    query = gdata.contacts.client.ContactsQuery()
    query.max_results = MAX_RESULTS
    feed = gd_client.GetContacts(q=query)
    return feed


def get_entry_name(entry):
    # Get name
    if entry.name is not None and entry.name.full_name is not None:
        name = entry.name.full_name.text
    # If no name, get organization
    elif entry.organization is not None:
        if entry.organization.name is not None:
            name = entry.organization.name.text
        else:
            name = entry.organization.text
    # If no name or organization, store name as "Unknown"
    else:
        name = "Unknown"
    return name


def fix_phone_numbers(gd_client, contact_feed):
    for i, entry in enumerate(contact_feed.entry):
        if not entry.phone_number or entry.deleted is not None:
            continue
        printed_name = False
        changed_entry = False
        for number in entry.phone_number:
            old_number = number.text
            # Check if correctly formatted already
            match = re.match(r"^\(\d{3}\) \d{3}-\d{4}\S*$", number.text)
            if match:
                # Skip correctly formatted phone numbers
                #print "  %s: perfect!" % number.text
                continue
            # Phone number is not correctly formatted
            if not printed_name:
                print "\n%s:  %s" % (i+1, get_entry_name(entry))
                printed_name = True
            match = re.search(r"^\+[023456789]", number.text)
            if match:
                # International (non-US) number, do nothing for now
                fixed = "no change, international"
                print "  %s -> %s" % (number.text, fixed)
                continue
            match = re.search(r"\+?1?\D{0,2}(\d{3})\D{0,2}(\d{3})\D{0,1}(\d{4})\s*(\S*)", number.text)
            if not match:
                fixed = "no change"
            else:
                fixed = "(%s) %s-%s%s" % (match.group(1), match.group(2), match.group(3), match.group(4))
                number.text = fixed
                changed_entry = True
            print "  %s -> %s" % (old_number, fixed)
        if changed_entry:
            #gd_client.Update(entry)
            pass


credentials = authenticate()

#http_auth = credentials.authorize(httplib2.Http())
gdata_auth = gdata.gauth.OAuth2TokenFromCredentials(credentials)

gd_client = gdata.contacts.client.ContactsClient()
gdata_auth.authorize(gd_client)

contact_feed = get_all_contacts(gd_client)
fix_phone_numbers(gd_client, contact_feed)
