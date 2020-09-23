import asyncio
import json
from http.client import responses
from urllib import parse

import aiohttp
from loguru import logger as log
from prettyprinter import pprint


class BlizzardAPI:

    def __init__(self, client_id, client_secret, region):
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region.lower()
        self.url = f'https://{self.region}.api.blizzard.com'
        self.authurl = f'https://{self.region}.battle.net/oauth/token'
        self.namespace = f'dynamic-classic-{self.region}'
        auth = aiohttp.BasicAuth(login=self.client_id, password=self.client_secret, encoding='utf-8')
        self.session = aiohttp.ClientSession(auth=auth)
        log.trace(f'BlizzrdAPI web session started')

    def close(self):
        if self.session is not None:
            log.trace(f'BlizzrdAPI web session ended')
            return self.session.close()

    async def authorize(self):
        form = aiohttp.FormData()
        form.add_field('grant_type', 'client_credentials')
        async with self.session.post(self.authurl, data=form, timeout=5) as response:
            resp = await response.json()
            respcode = response.status
        if respcode == 200 and 'access_token' in resp:
            self.access_token = resp['access_token']
            await self.session.close()
            self.session = aiohttp.ClientSession()
            log.debug('BlizzrdAPI session authorized token recieved')
        else:
            log.error(f'Error retrieving blizzard access token')
            await self.session.close()

    async def _get(self, path, **kwargs):
        params = {"access_token": self.access_token, "namespace": self.namespace, "region": self.region}
        params.update(kwargs)
        url = parse.urljoin(self.url, path)
        log.trace(f'BlizzardAPI Retreiving URL: {url}')
        try:
            async with self.session.get(url, params=params, timeout=5) as response:
                log.trace(f'BlizzardAPI HTTP Response: {response.status}')
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    log.warning(f'BlizzardAPI Failed Request [{responses[response.status]}] api:{self.api_key} {url}')
                    return json.loads(json.dumps([{'error': response.status}]))
                elif response.status - 400 >= 0 and response.status - 400 < 100:
                    log.debug(f'BlizzardAPI client error [{response.status}] [{responses[response.status]}] {url}')
                    return json.loads(json.dumps([{'error': response.status}]))
                elif response.status - 500 >= 0 and response.status - 500 < 100:
                    log.warning(f'BlizzardAPI server error [{response.status}] [{responses[response.status]}] {url}')
                    return json.loads(json.dumps([{'error': response.status}]))
                else:
                    log.error(f'BlizzardAPI UNKNOWN ERROR! [{response.status}] [{responses[response.status]}] {url}')
                    return json.loads(json.dumps([{'error': response.status}]))
        except asyncio.exceptions.TimeoutError:
            log.error(f'BlizzardAPI Timeout Error!')
            return json.loads(json.dumps([{'error': 'timeout'}]))

    async def realm_status(self, realm_id):
        path = f"/data/wow/connected-realm/{realm_id}"
        return await self._get(path)

