
# Medical Appointment System Backend

This project is a Spring Boot-based backend for a medical appointment system. It provides a REST API to manage doctors, their specializations, and related functionalities.

## Features
- CRUD operations for managing `Doctor` and `Specialization` entities.
- Pre-populated database for testing purposes.
- RESTful API for seamless frontend-backend integration.
- Configured CORS to allow cross-origin communication.

## Technologies Used
- Java 17
- Spring Boot 3
- Hibernate/JPA for ORM
- H2 Database for local testing
- Maven for dependency management

## Setup Instructions
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd medical_appointment_system_backend
   ```
2. Update `application.properties` to configure the database or use the provided H2 setup.
3. Build the project:
   ```bash
   mvn clean install
   ```
4. Run the application:
   ```bash
   mvn spring-boot:run
   ```
5. Access the API at `http://localhost:8080`.

## Entities
### Doctor
- Represents a medical professional.
- Fields: 
  - `id`: Unique identifier.
  - `name`: Doctor's name.
  - `specialization`: Associated specialization.

### Specialization
- Represents a doctor’s area of expertise.
- Fields:
  - `id`: Unique identifier.
  - `name`: Specialization name.

## Controllers
### DoctorController
Handles all CRUD operations for doctors.

#### Key Endpoints:
1. `POST /api/doctors` - Creates a new doctor.
2. `GET /api/doctors` - Retrieves all doctors.
3. `GET /api/doctors/specialization/{specializationId}` - Retrieves doctors by specialization.
4. `GET /api/doctors/{id}` - Retrieves a doctor by ID.
5. `PUT /api/doctors/{id}` - Updates an existing doctor.
6. `DELETE /api/doctors/{id}` - Deletes a doctor by ID.

## Configuration Files
### WebConfig.java
- Manages CORS configuration, enabling communication between the backend and frontend running on separate origins.

### SecurityConfig.java
- Previously configured for Okta authentication. Currently being refactored to simplify access control.

## Endpoints
HTTP Method | Endpoint                              | Description
------------|---------------------------------------|--------------------------------------------
GET         | `/api/doctors`                       | Retrieve all doctors
GET         | `/api/doctors/{id}`                  | Retrieve a doctor by ID
GET         | `/api/doctors/specialization/{id}`   | Retrieve doctors by specialization ID
POST        | `/api/doctors`                       | Create a new doctor
PUT         | `/api/doctors/{id}`                  | Update an existing doctor
DELETE      | `/api/doctors/{id}`                  | Delete a doctor by ID

Known Issues
	1.	Authentication: Okta integration is being refactored, and endpoints previously protected are now open.
	2.	Specialization Management: Specializations are pre-seeded and assume static IDs. Dynamic handling is needed for better flexibility.
	3.	CORS: Minor configuration issues have been observed in some cases.

Future Improvements
	•	Re-enable role-based authentication (e.g., Okta or another solution).
	•	Add CRUD operations for specializations.
	•	Improve error handling with detailed HTTP responses.
	•	Use Swagger/OpenAPI for API documentation.
	•	Increase test coverage for better reliability.

 
MIT License

Copyright (c) 2024 Medical Appointment System

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
