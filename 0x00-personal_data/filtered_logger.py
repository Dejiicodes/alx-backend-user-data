#!/usr/bin/env python3
"""Module for filtering and logging sensitive data."""

from typing import List
import re
import logging
import os
import mysql.connector


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str) -> str:
    """Redacts specified fields in a log message.

    Args:
        fields: A list of strings representing fields to redact.
        redaction: The string to replace the sensitive data with.
        message: The log message as a string.
        separator: The separator used to delineate fields in the message.

    Returns:
        A string with the specified fields redacted.
    """
    pattern = '|'.join(f'{field}=[^{separator}]*' for field in fields)
    return re.sub(pattern, lambda match: match.group(0).split('=')[0] + f'={redaction}', message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class for logging sensitive data."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize the formatter with fields to redact."""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record by redacting sensitive fields."""
        return filter_datum(
            self.fields,
            self.REDACTION,
            super().format(record),
            self.SEPARATOR
        )


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """Creates and returns a logger with a redacting formatter.

    Returns:
        A logging.Logger instance configured with a RedactingFormatter.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Establishes a connection to the MySQL database.

    Returns:
        A mysql.connector.connection.MySQLConnection object.
    """
    return mysql.connector.connect(
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    )


def main():
    """Main function to fetch and log data from the database."""
    db_connection = get_db()
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()

    for row in cursor:
        message = f"name={row[0]}; email={row[1]}; phone={row[2]}; ssn={row[3]}; password={row[4]}; ip={row[5]}; last_login={row[6]}; user_agent={row[7]};"
        logger.info(message)

    cursor.close()
    db_connection.close()


if __name__ == "__main__":
    main()

