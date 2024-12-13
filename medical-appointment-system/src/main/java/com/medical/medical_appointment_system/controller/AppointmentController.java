package com.medical.medical_appointment_system.controller;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.medical.medical_appointment_system.enums.AppointmentStatus;
import com.medical.medical_appointment_system.model.Appointment;
import com.medical.medical_appointment_system.model.Doctor;
import com.medical.medical_appointment_system.model.Patient;
import com.medical.medical_appointment_system.repository.AppointmentRepository;
import com.medical.medical_appointment_system.repository.DoctorRepository;
import com.medical.medical_appointment_system.repository.PatientRepository;

@RestController
@RequestMapping("/api/appointments")
public class AppointmentController {

    @Autowired
    private AppointmentRepository appointmentRepository;

    @Autowired
    private DoctorRepository doctorRepository;

    @Autowired
    private PatientRepository patientRepository;

    // Get all appointments
    @GetMapping
    public List<Appointment> getAllAppointments() {
        return appointmentRepository.findAll();
    }

    // Get a specific appointment by ID and validate Date of Birth
    @GetMapping("/{id}")
    public ResponseEntity<?> getAppointmentByIdAndDateOfBirth(
            @PathVariable Long id,
            @RequestParam String dateOfBirth) {
        Optional<Appointment> appointment = appointmentRepository.findById(id);

        if (appointment.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Sorry, no appointment with that information.");
        }

        // Validate the patient's date of birth
        Patient patient = appointment.get().getPatient();
        if (!patient.getDateOfBirth().toString().equals(dateOfBirth)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Sorry, no appointment with that information.");
        }

        return ResponseEntity.ok(appointment.get());
    }

    // Get all appointments by patient ID and validate Date of Birth
    @GetMapping("/patient/{id}")
    public ResponseEntity<?> getAppointmentsByPatientId(
            @PathVariable Long id,
            @RequestParam String dateOfBirth) {
        LocalDate dob = LocalDate.parse(dateOfBirth); // Convert to LocalDate if necessary
        List<Appointment> appointments = appointmentRepository.findByPatientIdAndPatientDateOfBirth(id, dob);

        if (appointments.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("No appointments found for this patient.");
        }

        return ResponseEntity.ok(appointments);
    }

    // Create a new appointment
    @PostMapping
    public ResponseEntity<Appointment> createAppointment(@RequestBody Map<String, Object> payload) {
        Appointment appointment = buildAppointmentFromPayload(payload);
        validateAppointment(appointment, null); // No current ID for new appointments
        Appointment savedAppointment = appointmentRepository.save(appointment);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedAppointment);
    }

    // Update an existing appointment
    @PutMapping("/{id}")
    public ResponseEntity<Appointment> updateAppointment(@PathVariable Long id, @RequestBody Map<String, Object> payload) {
        return appointmentRepository.findById(id).map(existingAppointment -> {
            if (!payload.containsKey("date") || !payload.containsKey("time")) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required fields: 'date' or 'time'.");
            }

            LocalDate newDate = LocalDate.parse(payload.get("date").toString());
            LocalTime newTime = LocalTime.parse(payload.get("time").toString());

            if (payload.containsKey("doctorId")) {
                Long doctorId = Long.valueOf(payload.get("doctorId").toString());
                Doctor doctor = doctorRepository.findById(doctorId)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Doctor not found."));
                existingAppointment.setDoctor(doctor);
            }

            existingAppointment.setDate(newDate);
            existingAppointment.setTime(newTime);

            validateAppointment(existingAppointment, id); // Pass the current appointment ID
            Appointment savedAppointment = appointmentRepository.save(existingAppointment);
            return ResponseEntity.ok(savedAppointment);
        }).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Appointment not found"));
    }

    // Delete an appointment
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAppointment(@PathVariable Long id) {
        if (appointmentRepository.existsById(id)) {
            appointmentRepository.deleteById(id);
            return ResponseEntity.noContent().build();
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Appointment not found");
        }
    }

    // Helper: Validate an appointment
    private void validateAppointment(Appointment appointment, Long currentAppointmentId) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime appointmentDateTime = LocalDateTime.of(appointment.getDate(), appointment.getTime());

        // Check for past appointments
        if (appointmentDateTime.isBefore(now)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot schedule an appointment in the past.");
        }

        // Check for doctor conflicts
        boolean doctorConflict = appointmentRepository
                .findByDoctorIdAndDateAndTime(appointment.getDoctor().getId(), appointment.getDate(), appointment.getTime())
                .stream()
                .anyMatch(a -> !a.getId().equals(currentAppointmentId)); // Exclude current appointment

        // Check for patient conflicts
        boolean patientConflict = appointmentRepository
                .findByPatientIdAndDateAndTime(appointment.getPatient().getId(), appointment.getDate(), appointment.getTime())
                .stream()
                .anyMatch(a -> !a.getId().equals(currentAppointmentId)); // Exclude current appointment

        if (doctorConflict) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "The doctor already has an appointment at this time.");
        }

        if (patientConflict) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "The patient already has an appointment at this time.");
        }
    }

    // Helper: Build appointment object from payload
    private Appointment buildAppointmentFromPayload(Map<String, Object> payload) {
        if (!payload.containsKey("doctorId") || payload.get("doctorId") == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or null 'doctorId'");
        }
        if (!payload.containsKey("patientId") || payload.get("patientId") == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or null 'patientId'");
        }
        if (!payload.containsKey("date") || payload.get("date") == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or null 'date'");
        }
        if (!payload.containsKey("time") || payload.get("time") == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or null 'time'");
        }

        Long doctorId = Long.valueOf(payload.get("doctorId").toString());
        Long patientId = Long.valueOf(payload.get("patientId").toString());
        LocalDate date = LocalDate.parse(payload.get("date").toString());
        LocalTime time = LocalTime.parse(payload.get("time").toString());

        Doctor doctor = doctorRepository.findById(doctorId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Doctor not found."));
        Patient patient = patientRepository.findById(patientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Patient not found."));

        Appointment appointment = new Appointment();
        appointment.setDoctor(doctor);
        appointment.setPatient(patient);
        appointment.setDate(date);
        appointment.setTime(time);
        appointment.setStatus(AppointmentStatus.SCHEDULED);

        return appointment;
    }
}