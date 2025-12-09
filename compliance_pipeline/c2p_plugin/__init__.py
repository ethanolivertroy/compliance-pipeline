# -*- mode:python; coding:utf-8 -*-

"""C2P Plugins for various policy engines."""

from compliance_pipeline.c2p_plugin.kyverno import PluginKyverno, PluginConfigKyverno
from compliance_pipeline.c2p_plugin.opa import PluginOPA, PluginConfigOPA

__all__ = [
    'PluginKyverno',
    'PluginConfigKyverno',
    'PluginOPA',
    'PluginConfigOPA',
]
