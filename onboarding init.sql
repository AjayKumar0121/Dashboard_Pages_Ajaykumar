-- Creating the onboarding database
CREATE DATABASE IF NOT EXISTS onboarding;

-- Connect to the onboarding database
\c onboarding

-- Create the ajay_table with all required fields
CREATE TABLE IF NOT EXISTS ajay_table (
  id SERIAL PRIMARY KEY,
  emp_name VARCHAR(255) NOT NULL,
  emp_email VARCHAR(255) UNIQUE NOT NULL,
  emp_gender VARCHAR(20),
  emp_marital_status VARCHAR(20),
  emp_dob DATE,
  emp_mobile VARCHAR(20),
  emp_aadhaar VARCHAR(12) UNIQUE,
  emp_pan VARCHAR(10),
  emp_address TEXT,
  emp_city VARCHAR(100),
  emp_state VARCHAR(100),
  emp_zipcode VARCHAR(20),
  emp_bank VARCHAR(255),
  emp_account VARCHAR(50),
  emp_ifsc VARCHAR(20),
  emp_bank_branch VARCHAR(100),
  emp_job_role VARCHAR(255),
  emp_department VARCHAR(255),
  emp_experience_status VARCHAR(20),
  emp_company_name VARCHAR(255),
  emp_years_of_experience INTEGER,
  emp_joining_date DATE,
  emp_profile_pic VARCHAR(255),
  emp_salary_slip VARCHAR(255),
  emp_offer_letter VARCHAR(255),
  emp_relieving_letter VARCHAR(255),
  emp_experience_certificate VARCHAR(255),
  emp_ssc_doc VARCHAR(255),
  ssc_school VARCHAR(255),
  ssc_year INTEGER,
  ssc_grade VARCHAR(20),
  emp_inter_doc VARCHAR(255),
  inter_college VARCHAR(255),
  inter_year INTEGER,
  inter_grade VARCHAR(20),
  inter_branch VARCHAR(100),
  emp_grad_doc VARCHAR(255),
  grad_college VARCHAR(255),
  grad_year INTEGER,
  grad_grade VARCHAR(20),
  grad_degree VARCHAR(100),
  grad_branch VARCHAR(100),
  resume VARCHAR(255),
  id_proof VARCHAR(255),
  signed_document VARCHAR(255),
  emp_terms_accepted BOOLEAN DEFAULT FALSE,
  primary_contact_name VARCHAR(255),
  primary_contact_relationship VARCHAR(100),
  primary_contact_phone VARCHAR(20),
  primary_contact_email VARCHAR(255),
  uan_number VARCHAR(50),
  pf_number VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add check constraints for Aadhaar and PAN formats
ALTER TABLE ajay_table
ADD CONSTRAINT check_aadhaar CHECK (emp_aadhaar ~ '^[1-9][0-9]{11}$'),
ADD CONSTRAINT check_pan CHECK (emp_pan ~ '^[A-Z]{5}[0-9]{4}[A-Z]$');
