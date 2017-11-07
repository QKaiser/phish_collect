''' Provides programmatic access to the data provided by Phishtank '''
import csv
import requests
import logging
import urllib
import chardet

from feeds.feed import Feed, FetchException
from models import Phish
from config import config


class PhishtankFeed(Feed):
    '''Implements the Phishtank phishing feed provider.'''

    def __init__(self):
        ''' Instantiates a new PhishtankFeed client'''
        self.feed = 'phishtank'
        self.url = config['phishtank']['url']
        self.last_seen = config['phishtank']['last_seen']

    def _process_rows(self, rows):
        '''
        Processes new phishing entries from the Phishtank API.

        Args:
            rows {list[str]} - The rows to process

        Row format:
        Index	Name	Description
        0	phish_id	The ID number by which Phishtank references this phishing submission.
        1	url	The phish URL as submitted to us. Because URLs can contain special characters, they are urlencoded on output.
        '''
        reader = csv.reader(rows, delimiter=',')
        entries = []
        urls_seen = []
        for record in reader:
            pid = record[0]
            try:
                url = urllib.unquote(record[1]).decode('utf-8')
            except:
                continue
            # For now, we won't re-process already seen URLs
            if Phish.exists(url) or Phish.clean_url(url) in urls_seen:
                continue
            urls_seen.append(Phish.clean_url(url))
            entries.append(Phish(pid=pid, url=url, feed=self.feed))
        return entries

    def get(self, offset=0):
        '''
        Gets the latest phishing URLs from the Phishtank feed.

        We send the last seen phishtank ID as an offset.

        Args:
            offset {str} - The offset phish ID to send to Phishtank
        '''
        if not offset:
            most_recent_phish = Phish.get_most_recent(feed='phishtank')
            if most_recent_phish:
                offset = most_recent_phish.pid
            else:
                # If there is no offset in the db and we weren't given one
                # as a kwarg, we'll use the one we have listed in the config
                # (chances are, this means that it's a first-run)
                offset = self.last_seen
        logging.info(
            'Fetching {} feed with last offset: {}'.format(self.feed, offset))
        results = []
        response = requests.get(self.url)
        if not response.ok:
            raise FetchException(
                'Error fetching response:\nStatus: {}\nResponse:{}'.format(
                    response.status_code, response.text))

        # The first row is the maximum phish id in our database.
        # The second row is the minimum phish id in our database
        # which is known to be online and functional. You can mark any id in your
        # database lower than this as offline without further checking
        # against our system.
        entries = response.text.splitlines()
	results = self._process_rows(entries[2:])
	if len(results) > 1:
		self.last_seen = results[1].pid
        return results
