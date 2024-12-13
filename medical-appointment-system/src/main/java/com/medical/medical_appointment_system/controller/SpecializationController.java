package com.medical.medical_appointment_system.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.medical.medical_appointment_system.model.Specialization;
import com.medical.medical_appointment_system.repository.SpecializationRepository;

@RestController
@RequestMapping("/api/specializations")
public class SpecializationController {

    @Autowired
    private SpecializationRepository specializationRepository;

    /**
     * Retrieve all specializations.
     * @return List of specializations wrapped in a ResponseEntity.
     */
    @GetMapping
    public ResponseEntity<List<Specialization>> getAllSpecializations() {
        List<Specialization> specializations = specializationRepository.findAll();
        return ResponseEntity.ok(specializations);
    }
}