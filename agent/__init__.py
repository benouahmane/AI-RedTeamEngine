"""Agent orchestration - a hand-rolled ReAct loop driven by the PTT.

The loop is implemented directly against the LLM client (`agent.llm`) rather
than via a framework: each step builds a compact task-tree + entity-state
context, asks the model for a single JSON action, and executes it. See
`agent.core.RedTeamAgent`.
""" 
from agent.core import RedTeamAgent
from agent.llm import LLMClient, get_llm_client
from agent.modes import ApprovalGateway

__all__ = ["RedTeamAgent", "LLMClient", "get_llm_client", "ApprovalGateway"]
