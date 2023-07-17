from typing import Dict, Tuple
import uuid
import time

from tokenservice.datastore import DataStore


class TokenService(Service):
    ACTIVE_DURATION_SEC = 86400

    def __init__(
        self,
        config: Dict
    ) -> None:
        Service.__init(config)
        self.db = DataStore(config['db'])

    def start(self):
        # TODO
        pass

    def stop(self):
        # TODO
        pass

    async def get_or_create_token(self, id: str) -> Tuple[str, float]:
        issued, expire = self.db.select_by_id(id)
        if issued:
            if await self.update(id, issued):
                return self.db.select_by_id(id)
            else:
                self.db.delete(id)
        token = uuid.uuid4().hex
        expire = time.time() + self.ACTIVE_DURATION_SEC
        self.db.insert(id, token, expire)
        return token, expire

    async def create_token(self, id: str) -> str:
        issued, expire = self.db.select_by_id(id)
        if issued:
            self.db.delete(id)
        token = uuid.uuid4().hex
        expire = time.time() + self.ACTIVE_DURATION_SEC
        self.db.insert(id, token, expire)
        return token

    def isvalid(self, id: str, token: str) -> bool:
        issued, expire = self.db.select_by_id(id)
        if issued is None:
            return False
        return issued == token and time.time() < expire

    async def update(self, id: str, token: str) -> bool:
        if self.isvalid(id, token):
            self.db.update_token_expire(id, time.time() + self.ACTIVE_DURATION_SEC)
            return True
        else:
            return False
