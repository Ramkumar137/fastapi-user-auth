from pydantic import BaseModel, constr

class UserCreate(BaseModel):
    username:constr(min_length=3,max_length=20)
    password:constr(min_length=6)
class UserLogin(BaseModel):
    username:str
    password:str