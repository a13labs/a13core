package providers

type User struct {
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Role      string   `json:"role"`
	AppTokens []string `json:"app_tokens"`
}

type UserView struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type Users struct {
	Users []User `json:"users"`
}

type AppToken struct {
	Token      string `json:"token"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	Expiration string `json:"expiration"`
}
