package com.medical.medical_appointment_system.repository;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.medical.medical_appointment_system.model.Appointment;

public interface AppointmentRepository extends JpaRepository<Appointment, Long> {

    // Find all appointments by doctor on a specific date
    List<Appointment> findByDoctorIdAndDate(Long doctorId, LocalDate date);

    // Find all appointments by patient on a specific date
    List<Appointment> findByPatientIdAndDate(Long patientId, LocalDate date);

    // Find overlapping appointments for a patient on the same day and time range
    List<Appointment> findByPatientIdAndDateAndTimeBetween(Long patientId,
                                                           LocalDate date,
                                                           LocalTime startTime,
                                                           LocalTime endTime);

    // Find overlapping appointments for a doctor on the same day and time range
    List<Appointment> findByDoctorIdAndDateAndTimeBetween(Long doctorId,
                                                          LocalDate date,
                                                          LocalTime startTime,
                                                          LocalTime endTime);

    // Find a specific appointment by doctor ID, date, and time
    List<Appointment> findByDoctorIdAndDateAndTime(Long doctorId, LocalDate date, LocalTime time);

    // Find a specific appointment by patient ID, date, and time
    List<Appointment> findByPatientIdAndDateAndTime(Long patientId, LocalDate date, LocalTime time);

    // Find appointments by patient ID and patient date of birth

}