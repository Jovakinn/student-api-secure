package com.example.securedemo.student;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@Slf4j
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Adam Smith"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        log.info(String.valueOf(student));
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable(name = "studentId") Integer studentId) {
        log.info(String.valueOf(studentId));
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable(name = "studentId") Integer studentId,
                              @RequestBody Student student) {
        log.info(String.format("%s %s", studentId, student));
    }
}
