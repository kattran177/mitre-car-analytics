"""Unit tests for the grammar-based transpiler."""

import pytest
from grammar.normalise import normalise
from grammar.parser import parse, ParseError
from grammar.translate import ast_to_splunk


class TestNormalise:
    def test_single_equals_to_double(self):
        raw = 'x = filter y where (exe = "cmd.exe")'
        result = normalise(raw)
        assert '==' in result
        assert 'exe  == ' in result

    def test_boolean_case(self):
        assert 'and' in normalise('x AND y')
        assert 'or' in normalise('x OR y')

    def test_pipe_escape(self):
        assert '|' in normalise('{{pipe}}')

    def test_smart_quotes(self):
        result = normalise('\u201chello\u201d')
        assert '"hello"' in result

    def test_wildcard_quoting(self):
        raw = 'x = filter y where (exe == *cmd*)'
        result = normalise(raw)
        assert '"*cmd*"' in result

    def test_missing_where(self):
        raw = 'x = filter y (exe == "cmd.exe")'
        result = normalise(raw)
        assert 'where' in result

    def test_missing_close_paren_before_output(self):
        raw = 'x = filter y where (exe == "cmd.exe"\noutput x'
        result = normalise(raw)
        assert 'output' in result
        # Should have balanced parens before output
        before_output = result.split('output')[0]
        assert before_output.count('(') == before_output.count(')')


class TestParser:
    def test_simple_search_filter_output(self):
        code = 'process = search Process:Create\ncmd = filter process where (exe == "cmd.exe")\noutput cmd'
        ast = parse(normalise(code))
        assert len(ast) == 3
        assert ast[0]['type'] == 'search'
        assert ast[1]['type'] == 'filter'
        assert ast[2]['type'] == 'output'

    def test_search_stmt(self):
        ast = parse(normalise('x = search Process:Create'))
        assert ast[0]['models'][0] == {'object': 'Process', 'action': 'Create'}

    def test_filter_equality(self):
        code = 'x = search Process:Create\ny = filter x where (exe == "test.exe")\noutput y'
        ast = parse(normalise(code))
        cond = ast[1]['condition']
        assert cond['op'] == '=='
        assert cond['value'] == 'test.exe'

    def test_filter_and_or(self):
        code = 'x = search Process:Create\ny = filter x where (a == "1" and b == "2")\noutput y'
        ast = parse(normalise(code))
        cond = ast[1]['condition']
        assert cond['op'] == 'and'

    def test_reject_invalid(self):
        with pytest.raises(ParseError):
            parse('not valid pseudocode at all')

    def test_output_multiple(self):
        code = 'x = search Process:Create\noutput x, y, z'
        ast = parse(normalise(code))
        assert ast[1]['variables'] == ['x', 'y', 'z']


class TestTranslate:
    def test_basic_process_query(self):
        code = 'p = search Process:Create\nf = filter p where (exe == "cmd.exe")\noutput f'
        ast = parse(normalise(code))
        splunk = ast_to_splunk(ast)
        assert 'EventCode=1' in splunk
        assert 'Image="cmd.exe"' in splunk
        assert '| table' in splunk

    def test_not_equals(self):
        code = 'p = search Process:Create\nf = filter p where (parent_exe != "explorer.exe")\noutput f'
        ast = parse(normalise(code))
        splunk = ast_to_splunk(ast)
        assert 'ParentImage!="explorer.exe"' in splunk

    def test_file_create(self):
        code = 'f = search File:Create\nx = filter f where (file_path == "*.dmp")\noutput x'
        ast = parse(normalise(code))
        splunk = ast_to_splunk(ast)
        assert 'EventCode=11' in splunk
        assert 'TargetFilename' in splunk

    def test_registry(self):
        code = 'r = search Registry:Create\nx = filter r where (key == "*\\\\CLSID\\\\*")\noutput x'
        ast = parse(normalise(code))
        splunk = ast_to_splunk(ast)
        assert 'EventCode=12' in splunk
        assert 'TargetObject' in splunk


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
