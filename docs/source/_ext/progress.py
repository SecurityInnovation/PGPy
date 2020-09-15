__author__ = 'magreene'

import collections
import re

from docutils import nodes
from docutils.parsers.rst import Directive
from docutils.statemachine import StringList


class progress(nodes.General, nodes.Element):
    tagname = 'progress'


class ProgressTable(Directive):
    has_content = True
    required_arguments = 1
    final_argument_whitespace = True
    option_spec = {'text': str}

    def create_headrow(self, label="Progress", classes=('prog-top-label',)):
        hrow = nodes.row()
        hrow += nodes.entry('', nodes.paragraph(text=label), classes=['head'] + list(classes))
        hrow += nodes.entry('', nodes.paragraph(text='PLACEHOLDER'), classes=['PLACEHOLDER'])
        return hrow

    def create_progtable(self, **attrs):
        _attrs = {
            'classes': ['progress', 'outer', 'docutils', 'field-list'],
            'colwidths': [20, 80]
        }
        _attrs.update(attrs)

        # create container elements
        node = nodes.table(classes=_attrs['classes'])
        tgroup = nodes.tgroup(cols=2)
        thead = thead = nodes.thead()
        thead += self.create_headrow()
        tbody = nodes.tbody()

        # tgroup gets:
        #  - colspec
        #  - thead
        #  - tbody
        for w in _attrs['colwidths']:
            tgroup += nodes.colspec(colwidth=w)

        # assemble the hierarchy
        tgroup += thead
        tgroup += tbody
        node += tgroup

        # return the table
        return node

    def add_progbar(self, row, val, max):
        entry = nodes.entry(classes=['progcell', 'field-value'])
        pbar = progress(value=val, max=max)
        entry += pbar

        row.replace(row.children[-1], entry)

    def run(self):
        secid = [self.arguments[0].lower().replace(' ', '-')]
        section = nodes.section(ids=secid)
        section.document = self.state.document

        section += nodes.title(text=self.arguments[0])

        # parse the 'text' option into the section, as a paragraph.
        self.state.nested_parse(StringList([self.options['text']], parent=self), 0, section)

        node = self.create_progtable()
        section.children[-1] += node

        head = node.children[0].children[-2].children[0]
        body = node.children[0].children[-1]

        comps = collections.OrderedDict()
        cur = ""

        for line in self.content:
            # new list
            nl = re.match(r'^:(?P<component>.+):$', line)
            if nl is not None:
                if cur != "":
                    # finish up shrow
                    self.add_progbar(shrow, len([c for c in comps[cur] if c is True]), len(comps[cur]))

                cur = nl.groupdict()['component']

                if cur not in comps:
                    comps[cur] = []

                # shrow is the section header row
                shrow = self.create_headrow(cur, classes=['field-name'])
                body += shrow

                continue

            nl = re.match(r'^\s+- (?P<item>[^,]+),\s+(?P<value>(True|False))(, (?P<description>.+)$)?', line)
            if nl is not None:
                nl = nl.groupdict()
                comps[cur].append(True if nl['value'] == "True" else False)
                tr = nodes.row()
                tr += nodes.description('',
                                        nodes.inline(text="\u2713" if comps[cur][-1] else " "),
                                        classes=['field-name', 'progress-checkbox'])
                text_description = nodes.inline()
                self.state.nested_parse(StringList(['{:s}'.format(nl['description'].lstrip() if nl['description'] is not None else ' ')], parent=self), 0, text_description)

                tr += nodes.description('',
                                        nodes.strong(text='{:s} '.format(nl['item'])),
                                        text_description,
                                        classes=['field-value'])
                body += tr

        if self.content:
            # finish up the final hrow
            self.add_progbar(shrow, len([c for c in comps[cur] if c == True]), len(comps[cur]))


        # and fill in the end of mrow
        self.add_progbar(head, len([c for r in comps.values() for c in r if c == True]), len([c for r in comps.values() for c in r]))


        return [section]


def visit_progress(self, node):
    attrs = {'value': 0,
             'max': 0}
    for a in attrs.keys():
        if a in node.attributes:
            attrs[a] = node.attributes[a]

    self.body.append('<label>{}/{}</label>'.format(attrs['value'], attrs['max']))
    self.body.append(self.starttag(node, node.tagname, **attrs))
    self.body.append('</progress>')


def depart_progress(self, node):
    pass


def setup(app):
    app.add_stylesheet('progress.css')
    app.add_node(progress, html=(visit_progress, depart_progress))
    app.add_directive('progress', ProgressTable)
