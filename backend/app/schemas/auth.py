from pydantic import BaseModel, Field


class UserOut(BaseModel):
    id: str
    username: str
    email: str | None = None
    display_name: str = ""
    role: str
    created_at: str
    active: bool
    mfa_enabled: bool = False
    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str
    password: str


class SetupRequest(BaseModel):
    username: str
    password: str = Field(..., min_length=12)
    # Required when the SETUP_TOKEN env var is set (first-boot admin claim)
    setup_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12)


class UpdateProfileRequest(BaseModel):
    display_name: str
    email: str | None = None


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=12)
    display_name: str | None = None
    email: str | None = None
    role: str = "user"


class UpdateUserRequest(BaseModel):
    display_name: str | None = None
    email: str | None = None
    role: str | None = None
    active: bool | None = None
    password: str | None = Field(None, min_length=12)


class MfaSetupResponse(BaseModel):
    uri: str
    secret: str


class MfaEnableRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    code: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str
