-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, is_chirpy_red)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2,
    FALSE
)
RETURNING *;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: ResetEmailPass :one
UPDATE users
SET updated_at = NOW(), email = $2, hashed_password = $3
WHERE id = $1
RETURNING *;
