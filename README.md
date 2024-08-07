# MongoDB Backend for Sigma

This project provides a MongoDB backend for Sigma, allowing Sigma rules to be converted into MongoDB queries. The backend supports various Sigma conditions and expressions, enabling comprehensive rule conversion and querying capabilities.

## Features

- Conversion of Sigma rules into MongoDB queries
- Support for AND, OR, and NOT conditions
- Handling of comparison operators, regular expressions, and value lists
- Support for correlation methods using MongoDB aggregation framework

## Usage

1. Import the necessary modules and create an instance of `MongoDBBackend`:
    ```python
    from sigma.backends.mongodb import MongoDBBackend
    from sigma.collection import SigmaCollection

    # Create an instance of MongoDBBackend
    mongo_backend = MongoDBBackend()
    ```

2. Load and convert a Sigma rule:
    ```python
    rule_text = """
    title: Example Rule
    logsource:
        category: example
        product: example_product
    detection:
        selection:
            field1: value1
            field2: value2
        condition: selection
    """
    rule = SigmaCollection.from_yaml(rule_text)
    converted_query = mongodb_backend.convert(rule)
    print(converted_query)
    ```


