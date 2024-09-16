import uuid
from datetime import datetime
from sqlalchemy import text
from transactional import transactional

class CloverDAL:
    def __init__(self, db_session):
        self.db_session = db_session

    @transactional
    def create_or_update_token(self, merchant_id, access_token, refresh_token=None, expires_at=None):
        """
        Insert a new token or update an existing token for a merchant.
        """
        now = datetime.utcnow()
        query = """
            INSERT INTO clover_tokens (id, merchant_id, access_token, refresh_token, expires_at, created_at, updated_at)
            VALUES (%(id)s, %(merchant_id)s, %(access_token)s, %(refresh_token)s, %(expires_at)s, %(now)s, %(now)s)
            ON CONFLICT (merchant_id) 
            DO UPDATE SET 
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at = EXCLUDED.expires_at,
                updated_at = EXCLUDED.updated_at;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {
                'id': str(uuid.uuid4()),
                'merchant_id': merchant_id,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_at': expires_at,
                'now': now
            })
            self.db_session.commit()

    @transactional
    def get_token_by_merchant_id(self, merchant_id):
        """
        Retrieve the stored access token and refresh token for a given merchant.
        """
        query = """
            SELECT access_token, refresh_token, expires_at FROM clover_tokens
            WHERE merchant_id = %(merchant_id)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'merchant_id': merchant_id})
            result = cursor.fetchone()

        if result:
            return {
                'access_token': result[0],
                'refresh_token': result[1],
                'expires_at': result[2]
            }
        return None

    @transactional
    def delete_token_by_merchant_id(self, merchant_id):
        """
        Delete the stored token for a given merchant.
        """
        query = """
            DELETE FROM clover_tokens WHERE merchant_id = %(merchant_id)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'merchant_id': merchant_id})
            self.db_session.commit()
