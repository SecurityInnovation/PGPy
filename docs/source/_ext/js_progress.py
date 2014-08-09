__author__ = 'magreene'

import collections
import re

from docutils import nodes
from docutils.parsers.rst import Directive
from docutils.parsers.rst import directives
from docutils.statemachine import StringList


class JSProgressCell(nodes.General, nodes.TextElement):
    tagname = 'td'


class JSProgressTable(Directive):
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
            'classes': ['progress', 'outer'],
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
                    shrow.replace(shrow.children[-1], JSProgressCell(text="{:d}/{:d}".format(len([c for c in comps[cur] if c == True]), len(comps[cur]))))

                cur = nl.groupdict()['component']

                if cur not in comps:
                    comps[cur] = []

                # shrow is the section header row
                shrow = self.create_headrow(cur, classes=['prog-sec-label'])
                body += shrow

                continue

            nl = re.match(r'^\s+- (?P<item>[^,]+),\s+(?P<value>(True|False))(, (?P<description>.+)$)?', line)
            if nl is not None:
                nl = nl.groupdict()
                comps[cur].append(True if nl['value'] == "True" else False)
                tr = nodes.row()
                tr += nodes.description('', nodes.inline(text="\u2713" if comps[cur][-1] else " "), classes=['progress-checkbox'])
                tr += nodes.description('', nodes.strong(text='{:s} '.format(nl['item'])),
                                        nodes.inline(text='{:s}'.format(nl['description'] if nl['description'] is not None else ' ')))
                body += tr

        # finish up the final hrow
        shrow.replace(shrow.children[-1], JSProgressCell(text="{:d}/{:d}".format(len([c for c in comps[cur] if c == True]), len(comps[cur]))))


        # and fill in the end of mrow
        head.replace(head.children[-1], JSProgressCell(text="{:d}/{:d}".format(len([c for r in comps.values() for c in r if c == True]),
                                                                               len([c for r in comps.values() for c in r]))))

        return [section]


def visit_progcell(self, node):
    table = node.parent.parent
    row = node.parent

    text = node.astext()
    if text != '':
        node.remove(text)
        encoded = self.encode(text)

    if 'outer' in table.parent.parent.attributes['classes']:
        classes = 'progtop'

    self.body.append(self.starttag(node, 'th' if isinstance(row.parent, nodes.thead) else 'td', '', CLASS=classes))
    self.body.append(self.starttag(node, 'div', '', CLASS='ui-progressbar'))
    self.body.append(self.starttag(node, 'div', '', CLASS='progress-label'))

    if text != '':
        self.body.append(encoded)

def depart_progcell(self, node):
    self.body.append('</div></div>')
    self.depart_description(node)


def progress_insert_js(app, doctree):
    if len(doctree.traverse(JSProgressCell)) > 0:
        # add jquery-ui
        app.add_javascript('jquery-ui.min.js')
        app.add_stylesheet('jquery-ui.min.css')
        app.add_stylesheet('jquery-ui.theme.min.css')

        # add progress.{js,css}
        app.add_javascript('progress.js')
        app.add_stylesheet('progress.css')


def setup(app):
    # add directive(s): progbar, and some nodes to handle some pieces
    # app.add_node(JSProgressTableNode,
    #              html=(visit_progress, depart_progress))
    app.add_node(JSProgressCell,
                 html=(visit_progcell, depart_progcell))

    # add a hook to insert the progress bar javascript into a page using progress
    app.connect('doctree-read', progress_insert_js)

    app.add_directive('progress', JSProgressTable)
