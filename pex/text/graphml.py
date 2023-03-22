"""
MIT License

Copyright (c) 2020-2022 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from typing import Optional

import re
import networkx as nx
import random
import string


class GraphML(object):
    """ Subclass of pex.text module.

    This subclass of pex.text module is a representation of GraphML file
    parser.
    """

    FLOW_INSTRUCTIONS = {}
    FLOW_INSTRUCTIONS['x86'] = ['call', 'jae', 'jb', 'jbe', 'jc', 'jcxz', 'je', 'jecxz', 'jg', 'jge', 'jl', 'jle', 'jmp', 'jna',
                                'jnae', 'jnb', 'jnbe', 'jnc', 'jne', 'jng', 'jnge', 'jnl', 'jnle', 'jno', 'jnp', 'jns', 'jnz', 'jo',
                                'jp', 'jpe', 'jpo', 'js', 'jz']
    FLOW_INSTRUCTIONS['x64'] = FLOW_INSTRUCTIONS['x86'] + ['jrcxz']

    def __init__(self, file_path: str, arch: Optional[str] = None, name: Optional[str] = None) -> None:
        """ Initialize GraphML parser.

        :param str file_path: path to the GraphML file
        :param Optional[str] arch: architeture
        :param Optional[str] name: name
        :return None: None
        """

        self.graphml = nx.read_graphml(file_path)

        self.blocks = self.create_path([
          (node_id, node) for node_id, node in self.graphml.nodes(data=True) if node['type'] == 'block'
        ], self.graphml.edges)

        self.blocks = [{'node': block, 'instructions': self.process_block(block)} for block in self.blocks]

        self.arch = arch
        self.name = name

        self.label_prefix = ''.join(random.choices(string.ascii_lowercase, k=4))
        self.labeler = lambda address: f"loc_{self.label_prefix}{address:0>4x}"
    
    def generate_assembly_source(self) -> str:
        """ Generate assembler code from GraphML.

        :return str: assembler code
        :raises RuntimeError: with trailing error message
        """

        source_lines = []
        labeled = []
        label_refs = []

        for block in self.blocks:
            if self.arch in ['x86', 'x64']:
                source_lines.append(f"{self.labeler(block['node']['address'])}:")
                labeled.append(block['node']['address'])
                instructions = [f"db {' '.join(['0x' + b for b in node['instruction.hex'].strip().split()])}" for node in block['instructions']]
            else:
                instructions = [node['instruction.source'] for node in block['instructions']]

            if self.arch:
                if self.arch not in self.FLOW_INSTRUCTIONS:
                    raise RuntimeError('Unsupported architecture!')

                for i, node in enumerate(block['instructions']):
                    match = None

                    if node['instruction.source']:
                        match = re.search(r'^(?P<mnemonic>\S+)\s+(?P<address>0x[0-9a-fA-F]+)$', node['instruction.source'])

                    if match and match.group('mnemonic') in self.FLOW_INSTRUCTIONS[self.arch]:
                        address = int(match.group('address'), 16)
                        instructions[i] = f"{match.group('mnemonic')} {self.labeler(address)}"
                        label_refs.append(address)

            source_lines += instructions

        if not all(address in labeled for address in label_refs):
            raise RuntimeError('Missing label reference!')

        if self.name:
            source_lines = [f"{self.name}:\n"] + [f"  {source_line}" for source_line in source_lines]

        return "\n".join(source_lines) + "\n"

    def process_block(self, block: str) -> str:
        """ Process the specified graph element which represents a single basic block in assembly.

        :param str block: single basic block
        :return str: processed block
        """

        subgraph = block['subgraph']
        instructions = [
          (node_id, node) for node_id, node in subgraph.nodes(data=True) if node['type'] == 'instruction'
        ]

        return self.create_path(instructions, subgraph.edges)
    
    @staticmethod
    def create_path(nodes: list, edges: list) -> str:
        """ Create path from node to edge.

        :param list nodes: nodes
        :param list edges: edges
        :return str: path
        """

        path = []

        targets = [edge[1] for edge in edges]
        choices = [node for node in nodes.values() if node['type'] == 'block' and node.id not in targets]

        while choices:
            selection = random.choice(choices)
            choices.remove(selection)
            path.append(selection)

            successors = [nodes[edge[1]] for edge in edges if edge[0] == selection.id]
            for successor in successors:
                if successor not in path and all(nodes[edge[0]] in path for edge in successor.in_edges()):
                    choices.append(successor)

        return path
