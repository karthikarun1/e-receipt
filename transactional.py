from functools import wraps

def transactional(func):
    """
    A decorator to wrap database operations in a transaction.
    Rolls back in case of an exception, otherwise commits the transaction.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        self = args[0]  # Assuming `self` is the first argument
        session = self.db_session
        try:
            result = func(*args, **kwargs)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            raise e
    return wrapper
