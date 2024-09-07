-- Create courses table
CREATE TABLE courses (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    instructor VARCHAR(100)
);

-- Create students table
CREATE TABLE students (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    date_of_birth DATE
);

-- Create course_students junction table
CREATE TABLE course_students (
    course_id INT REFERENCES courses(id),
    student_id INT REFERENCES students(id),
    enrollment_date DATE NOT NULL,
    PRIMARY KEY (course_id, student_id)
);

-- Insert sample courses
INSERT INTO courses (title, description, instructor) VALUES
('Introduction to Philosophy', 'Explore fundamental questions about existence, knowledge, and ethics.', 'Dr. Anne Johnson'),
('World Literature', 'Study classic and contemporary works of literature from around the world.', 'Prof. Sarah Lee'),
('History of Western Art', 'Survey the development of Western art from antiquity to the present.', 'Dr. Michael Carter'),
('Introduction to Psychology', 'Learn the basics of human behavior, cognition, and emotion.', 'Dr. Rachel Green'),
('Sociology of Gender', 'Examine the social constructs of gender and their impact on society.', 'Prof. David Martinez');

-- Insert sample students
INSERT INTO students (first_name, last_name, email, date_of_birth) VALUES
('Sophia', 'Adams', 'sophia.adams@example.com', '2001-05-15'),
('Liam', 'Baker', 'liam.baker@example.com', '2002-08-22'),
('Olivia', 'Clark', 'olivia.clark@example.com', '2000-03-10'),
('Noah', 'Davis', 'noah.davis@example.com', '2003-11-30'),
('Emma', 'Evans', 'emma.evans@example.com', '2001-07-18');

-- Enroll students in courses
INSERT INTO course_students (course_id, student_id, enrollment_date) VALUES
(1, 1, '2024-01-15'),
(1, 2, '2024-01-16'),
(2, 2, '2024-02-01'),
(2, 3, '2024-02-03'),
(3, 3, '2024-03-10'),
(3, 4, '2024-03-12'),
(4, 4, '2024-04-05'),
(4, 5, '2024-04-07'),
(5, 5, '2024-05-20'),
(5, 1, '2024-05-22');