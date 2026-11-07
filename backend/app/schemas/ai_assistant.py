"""
Pydantic schemas for the AI Security Assistant.
"""

import uuid
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str = Field(..., description="user or assistant")
    content: str


class AssistantChatRequest(BaseModel):
    message: str = Field(..., min_length=2, description="User question or inquiry")
    scan_id: Optional[uuid.UUID] = Field(None, description="Optional scan ID for contextual reasoning")
    history: Optional[List[ChatMessage]] = Field(default_factory=list)


class AssistantChatResponse(BaseModel):
    response: str
    context_used: bool = False
    target_url: Optional[str] = None
    verdict: Optional[str] = None
    suggested_actions: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)

