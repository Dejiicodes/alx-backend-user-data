#!/usr/bin/env python3
"""Filtered Logger Module

This module contains functions and classes for filtering and logging
sensitive personal data, such as PII (Personally Identifiable Information).
"""

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
    """Redacts sensitive information from a log message.

    Args:
        fields (List[str]): A list of fields to redact.
        redaction (str): The string that will replace the sensitive data.
        message (str): The log message to be filtered.
        separator (str): The character separating fields in the log message.

    Returns:
        str: The log message with the sensitive fields redacted.
    """
    for field in fields:
        message = re.sub(
            f"{field}=[^{separator}]*",
            f"{field}={redaction}",
            message
        )
    return message


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class for logging sensitive data."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initializes the formatter with fields to redact.

        Args:
            fields (List[str]): A list of fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record by redacting sensitive fields.

        Args:
            record (logging.LogRecord): The log record to be formatted.

        Returns:
            str: The formatted log record with sensitive fields redacted.
        """
        return filter_datum(
            self.fields,
            self.REDACTION,
            super().format(record),
            self.SEPARATOR
        )


PII_FIELDS = ["name", "email", "phone", "ssn", "password"]


def get_logger() -> logging.Logger:
    """Creates and configures a logger for logging user data.

    Returns:
        logging.Logger: A logger instance configured with a
                        RedactingFormatter.
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
        mysql.connector.connection.MySQLConnection: A MySQL database connection.
    """
    return mysql.connector.connect(
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    )


def main():
    """Main function that retrieves data from the database and logs it."""
    db_connection = get_db()
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()

    for row in cursor:
        message = (
            f"name={row[0]}; email={row[1]}; phone={row[2]}; "
            f"ssn={row[3]}; password={row[4]}; ip={row[5]}; "
            f"last_login={row[6]}; user_agent={row[7]};"
        )
        logger.info(message)

    cursor.close()
    db_connection.close()


if __name__ == "__main__":
    main()
