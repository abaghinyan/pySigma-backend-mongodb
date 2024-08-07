from sigma.conversion.state import ConversionState
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaString, SigmaExpansion
import re
from typing import ClassVar, Dict, Tuple, Pattern, Any

class MongoDBBackend(TextQueryBackend):
    """MongoDB backend."""
    
    name: ClassVar[str] = "MongoDB backend"
    formats: Dict[str, str] = {
        "default": "MongoDB queries",
    }
    requires_pipeline: bool = False

    query_expression: ClassVar[str] = '{query}'
    state_defaults: ClassVar[Dict[str, str]] = { "index": "*" }

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = '{{ {expr} }}'

    token_separator: str = ", "
    or_token: ClassVar[str] = "$or"
    and_token: ClassVar[str] = "$and"
    not_token: ClassVar[str] = "$not"
    eq_token: ClassVar[str] = '{{ "{field}": "{value}" }}'

    field_quote: ClassVar[str] = ""
    field_quote_pattern: ClassVar[Pattern] = re.compile("^[\\w.]+$")
    field_quote_pattern_negation: ClassVar[bool] = False

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = ".*"
    wildcard_single: ClassVar[str] = "."
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    startswith_expression: ClassVar[str] = '{{ "{field}": {{ "$regex": "^{value}" }} }}'
    endswith_expression: ClassVar[str] = '{{ "{field}": {{ "$regex": "{value}$" }} }}'
    wildcard_match_expression: ClassVar[str] = '{{ "{field}": {{ "$regex": "{value}" }} }}'

    re_expression: ClassVar[str] = '{{ "{field}": {{ "$regex": "{regex}" }} }}'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ('"',)
    re_escape_escape_char: bool = True

    cidr_expression: ClassVar[str] = '{{ "{field}": {{ "$regex": "{value}" }} }}'

    compare_op_expression: ClassVar[str] = '{{ "{field}": {{ {operator}: {value} }} }}'
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "$lt",
        SigmaCompareExpression.CompareOperators.LTE: "$lte",
        SigmaCompareExpression.CompareOperators.GT: "$gt",
        SigmaCompareExpression.CompareOperators.GTE: "$gte",
    }

    field_equals_field_expression: ClassVar[str] = '{{ "$expr": {{ "$eq": ["${field1}", "${field2}"] }} }}'
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)

    field_null_expression: ClassVar[str] = '{{ {field}: {{ "$exists": false }} }}'

    field_exists_expression: ClassVar[str] = '{{ {field}: {{ "$exists": true }} }}'
    field_not_exists_expression: ClassVar[str] = '{{ {field}: {{ "$exists": false }} }}'

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = '{{ {field}: {{ {op}: [{list}] }} }}'
    or_in_operator: ClassVar[str] = "$in"
    list_separator: ClassVar[str] = ", "

    correlation_methods: ClassVar[Dict[str, str]] = {
        "aggregate": "Correlation with aggregate command",
    }
    default_correlation_method: ClassVar[str] = "aggregate"
    default_correlation_query: ClassVar[str] = {"aggregate": "[ {search}, {aggregate}, {condition} ]"}
    temporal_correlation_query: ClassVar[str] = {"aggregate": "[ {search}, {typing}, {aggregate}, {condition} ]"}

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "[ {queries} ]"
    correlation_search_multi_rule_query_expression: ClassVar[
        str
    ] = '{{ {query} }}'
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = ", "

    typing_expression: ClassVar[str] = '{{ "$addFields": {{ "event_type": {{ "$switch": {{ "branches": [{queries}] }} }} }} }}'
    typing_rule_query_expression: ClassVar[str] = '{{ "case": {query}, "then": "{ruleid}" }}'
    typing_rule_query_expression_joiner: ClassVar[str] = ", "

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "aggregate": '{{ "$group": {{ "_id": {{ "$dateTrunc": {{ "date": "$@timestamp", "unit": "{timespan}" }} }}, "event_count": {{ "$sum": 1 }} }} }}{groupby}'
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "aggregate": '{{ "$group": {{ "_id": {{ "$dateTrunc": {{ "date": "$@timestamp", "unit": "{timespan}" }} }}, "value_count": {{ "$addToSet": "$field" }} }} }}{groupby}'
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "aggregate": '{{ "$group": {{ "_id": {{ "$dateTrunc": {{ "date": "$@timestamp", "unit": "{timespan}" }} }}, "event_type_count": {{ "$addToSet": "$event_type" }} }} }}{groupby}'
    }

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "s": "second",
        "m": "minute",
        "h": "hour",
        "d": "day",
        "w": "week",
        "M": "month",
        "y": "year",
    }
    referenced_rules_expression: ClassVar[Dict[str, str]] = {"aggregate": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[Dict[str, str]] = {"aggregate": ", "}

    groupby_expression_nofield: ClassVar = {"aggregate": ""}
    groupby_expression: ClassVar[Dict[str, str]] = {"aggregate": "{groupby}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"aggregate": ", {field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"aggregate": ""}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "aggregate": '{{ "$match": {{ "event_count": {{ {op}: {count} }} }} }}'
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "aggregate": '{{ "$match": {{ "value_count": {{ {op}: {count} }} }} }}'
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "aggregate": '{{ "$match": {{ "event_type_count": {{ {op}: {count} }} }} }}'
    }

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> dict:
        return '{{ "$or": [ {} ] }}'.format(", ".join([self.convert_condition(subcond, state) for subcond in cond.args]))

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> dict:
        return '{{ "$and": [ {} ] }}'.format(", ".join([self.convert_condition(subcond, state) for subcond in cond.args]))

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> dict:
        if isinstance(cond.args[0], ConditionOR):
            return '{{ "$nor": [ {} ] }}'.format(", ".join([self.convert_condition(subcond, state) for subcond in cond.args[0].args]))
        return '{{ "$nor": [ {} ] }}'.format(self.convert_condition(cond.args[0], state))

    def convert_condition_field_eq_value_keyword(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> dict:
        value = self.convert_value(cond.value)
        return '{{ "$text": {{ "$search": {} }} }}'.format( value)
    
    def convert_condition_field_eq_value(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> dict:
        field = self.convert_field_name(cond.field)
        value = self.convert_value(cond.value)
        return '{{ "{}": {} }}'.format(field, value)

    def convert_field_name(self, field: str) -> dict:
        return field

    def convert_value(self, val: Any) -> str:
        if isinstance(val, SigmaString):
            return '"{}"'.format(val)
        elif isinstance(val, str) and not val.startswith('"') and not val.endswith('"'):
            return '"{}"'.format(val.replace('"', '\\"'))
        elif isinstance(val, bool):
            return self.bool_values[val]
        else:
            return str(val)

    def escape_special_characters(self, text, regex=False):
        backslash = '\\\\'
        
        special_characters = {
            '\\': '\\' + backslash
        }
        text = text.replace('\\', backslash)
        
        if regex:
            # Special characters that need to be escaped
            special_characters = {
                '.': backslash + '.',
                '?': backslash + '?',
                '(': backslash + '(',
                ')': backslash + ')',
                '[': backslash + '[',
                ']': backslash + ']',
                '{': backslash + '{',
                '}': backslash + '}',
                '+': backslash + '+',
                '*': backslash + '*',
                '^': backslash + '^',
                '$': backslash + '$',
                '|': backslash + '|',
                '"': '\\"',
            }
            text = text.replace('\\', backslash * 2)

        
        translation_table = str.maketrans(special_characters)
        escaped_text = text.translate(translation_table)
        
        return escaped_text

    def convert_condition_field_eq_value_regex(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> dict:
        field = self.convert_field_name(cond.field)
        regex = cond.value.str()
        return '{{ "{}": {{ "$regex": "{}" }} }}'.format(field, regex)

    def convert_condition_field_eq_value_in(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> dict:
        field = self.convert_field_name(cond.field)
        values = ", ".join([self.convert_value(val) for val in cond.value])
        return '{{ "{}": {{ "$in": [ {} ] }} }}'.format(field, values)

    def convert_condition(self, cond: ConditionItem, state: ConversionState) -> dict:
        if isinstance(cond, ConditionAND):
            return self.convert_condition_and(cond, state)
        elif isinstance(cond, ConditionOR):
            return self.convert_condition_or(cond, state)
        elif isinstance(cond, ConditionNOT):
            return self.convert_condition_not(cond, state)
        elif isinstance(cond, ConditionFieldEqualsValueExpression) and isinstance(cond.value, SigmaString):
            if cond.value.to_plain().startswith("*") and cond.value.to_plain().endswith("*"):
                return self.wildcard_match_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(cond.value.to_plain()[1:-1], True))
            elif cond.value.to_plain().startswith("*"):
                return self.endswith_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(cond.value.to_plain()[1:], True))
            elif cond.value.to_plain().endswith("*"):
                return self.startswith_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(cond.value.to_plain()[:-1], True))
            else:
                return self.eq_token.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(cond.value.to_plain()))
        elif isinstance(cond, ConditionFieldEqualsValueExpression) and hasattr(cond.value, "sigma_to_re_flag"):
            return self.wildcard_match_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(cond.value.to_plain(), True))
        elif not hasattr(cond, 'field'):
            return self.convert_condition_field_eq_value_keyword(cond, state)
        elif isinstance(cond.value, list):
            return self.convert_condition_field_eq_value_in(cond, state)
        elif hasattr(cond, "value") and isinstance(cond.value, SigmaExpansion):
            value = cond.value
            if hasattr(cond.value, "values") and len(cond.value.values) > 0:
                value = cond.value.values[0]
            if value.to_plain().startswith("*") and value.to_plain().endswith("*"):
                return self.wildcard_match_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(value.to_plain()[1:-1], True))
            elif value.to_plain().startswith("*"):
                return self.endswith_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(value.to_plain()[1:], True))
            elif value.to_plain().endswith("*"):
                return self.startswith_expression.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(value.to_plain()[:-1], True))
            else:
                return self.eq_token.format(field=self.convert_field_name(cond.field), value=self.escape_special_characters(value.to_plain()))
        else:
            return self.convert_condition_field_eq_value(cond, state)
