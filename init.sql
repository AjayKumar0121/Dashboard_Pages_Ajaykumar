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

-- Create personnel table (using employees structure)
CREATE TABLE personnel (
    id VARCHAR(7) PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    role VARCHAR(40) NOT NULL,
    gender VARCHAR(10) NOT NULL,
    dob DATE NOT NULL,
    location VARCHAR(40) NOT NULL,
    email VARCHAR(50) NOT NULL,
    phone VARCHAR(10) NOT NULL,
    join_date DATE NOT NULL,
    experience INTEGER NOT NULL,
    skills TEXT NOT NULL,
    achievement TEXT NOT NULL,
    profile_image VARCHAR(255)
);

-- Create indexes for optimized querying
CREATE INDEX idx_email ON user_accounts(email);
CREATE INDEX idx_sessions_user ON auth_sessions(user_id);
CREATE INDEX idx_sessions_token ON auth_sessions(token);
CREATE INDEX idx_personnel_email ON personnel(email);

-- Insert sample users into user_accounts table (using same bcrypt hash for 'password123')
INSERT INTO user_accounts (username, email, password, profile_image) VALUES
('sampleuser', 'sample@gmail.com', '$2b$12$fPDP31Z0L5jKGw3QMGOkGOaeRWq2SCydyGnWWYGsrxLnIij/zbJTO', NULL);

-- Insert personnel data (based on employees table structure)
INSERT INTO personnel (id, name, role, gender, dob, location, email, phone, join_date, experience, skills, achievement, profile_image) VALUES
('ATS0050', 'Sample User', 'Junior Java Developer', 'Male', '1998-04-15', 'Hyd', 'sample@gmail.com', '6789012345', '2024-07-01', 1, 'Java, Spring Boot, Hibernate', 'Completed major bug fix in first month', NULL);
