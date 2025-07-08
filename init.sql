-- Drop any existing tables to avoid conflicts
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS employees CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;
DROP TABLE IF EXISTS staff CASCADE;
DROP TABLE IF EXISTS user_accounts CASCADE;
DROP TABLE IF EXISTS auth_sessions CASCADE;
DROP TABLE IF EXISTS personnel CASCADE;

-- Create user_accounts table
CREATE TABLE user_accounts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    profile_image TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    reset_token TEXT,
    reset_token_expiry TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create auth_sessions table
CREATE TABLE auth_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES user_accounts(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Create personnel table
CREATE TABLE personnel (
    emp_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    job_role VARCHAR(100),
    location VARCHAR(100),
    department VARCHAR(100),
    hire_date DATE,
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for optimized querying
CREATE INDEX idx_email ON user_accounts(email);
CREATE INDEX idx_sessions_user ON auth_sessions(user_id);
CREATE INDEX idx_sessions_token ON auth_sessions(token);
CREATE INDEX idx_personnel_email ON personnel(email);

-- Insert into user_accounts table (using provided bcrypt hash for 'password123')
INSERT INTO user_accounts (username, email, password, profile_image) VALUES
('abc', 'john@gmail.com', '$2b$12$fPDP31Z0L5jKGw3QMGOkGOaeRWq2SCydyGnWWYGsrxLnIij/zbJTO', NULL),
('abced', 'jane@gmail.com', '$2b$12$fPDP31Z0L5jKGw3QMGOkGOaeRWq2SCydyGnWWYGsrxLnIij/zbJTO', NULL),
('abcedf', 'alice@gmail.com', '$2b$12$fPDP31Z0L5jKGw3QMGOkGOaeRWq2SCydyGnWWYGsrxLnIij/zbJTO', NULL),
('emloyee', 'bob@gmail.com', '$2b$12$fPDP31Z0L5jKGw3QMGOkGOaeRWq2SCydyGnWWYGsrxLnIij/zbJTO', NULL),
('employye abc', 'emma@gmail.com', '$2b$12$fPDP31Z0L5jKGw3QMGOkGOaeRWq2SCydyGnWWYGsrxLnIij/zbJTO', NULL);

-- Insert into personnel table
INSERT INTO personnel (emp_id, name, email, job_role, location, department, hire_date, phone) VALUES
('ATS0121', 'ajay', 'john@gmail.com', 'Software Engineer', 'New York', 'Engineering', '2023-01-15', '123-456-7890'),
('ATS0141', 'AjayKumar', 'sample@gmail.com', 'Software Engineer', 'New York', 'Engineering', '2023-01-15', '123-456-7890'),
('ATS0132', 'Employee a', 'jane@gmail.com', 'Product Manager', 'San Francisco', 'Product', '2022-06-01', '234-567-8901'),
('ATS0143', 'Abc', 'alice@gmail.com', 'Data Analyst', 'Chicago', 'Analytics', '2023-03-10', '345-678-9012'),
('ATS0134', 'Abcd', 'bob@gmail.com', 'DevOps Engineer', 'Seattle', 'Engineering', '2021-11-20', '456-789-0123'),
('ATS0125', 'abcdef', 'abcedf@gmail.com', 'HR Specialist', 'Boston', 'Human Resources', '2022-09-05', '567-890-1234');
