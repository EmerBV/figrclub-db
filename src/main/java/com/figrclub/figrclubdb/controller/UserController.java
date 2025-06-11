package com.figrclub.figrclubdb.controller;

import com.figrclub.figrclubdb.domain.model.User;
import com.figrclub.figrclubdb.dto.UserDto;
import com.figrclub.figrclubdb.exceptions.AlreadyExistsException;
import com.figrclub.figrclubdb.exceptions.ResourceNotFoundException;
import com.figrclub.figrclubdb.request.CreateUserRequest;
import com.figrclub.figrclubdb.request.UserUpdateRequest;
import com.figrclub.figrclubdb.response.ApiResponse;
import com.figrclub.figrclubdb.service.user.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("${api.prefix}/users")
@Tag(name = "User Management", description = "Operations related to user management")
@Slf4j
public class UserController {

    private final IUserService userService;

    @GetMapping("/{userId}")
    @Operation(summary = "Get user by ID", description = "Retrieve a user by their unique identifier")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> getUserById(
            @Parameter(description = "User ID", required = true)
            @PathVariable Long userId) {
        try {
            log.info("Fetching user with ID: {}", userId);
            User user = userService.getUserById(userId);
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.ok(new ApiResponse("User retrieved successfully", userDto));
        } catch (ResourceNotFoundException e) {
            log.warn("User not found with ID: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        }
    }

    @GetMapping
    @Operation(summary = "Get all users", description = "Retrieve all users with pagination")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> getAllUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "id") String sortBy,
            @Parameter(description = "Sort direction")
            @RequestParam(defaultValue = "asc") String sortDirection,
            @Parameter(description = "Show only active users")
            @RequestParam(defaultValue = "true") boolean activeOnly) {

        try {
            Sort.Direction direction = sortDirection.equalsIgnoreCase("desc")
                    ? Sort.Direction.DESC : Sort.Direction.ASC;
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

            Page<User> usersPage = activeOnly
                    ? userService.findActiveUsers(pageable)
                    : userService.findAllUsers(pageable);

            Page<UserDto> userDtoPage = usersPage.map(userService::convertUserToDto);

            Map<String, Object> response = new HashMap<>();
            response.put("users", userDtoPage.getContent());
            response.put("currentPage", userDtoPage.getNumber());
            response.put("totalItems", userDtoPage.getTotalElements());
            response.put("totalPages", userDtoPage.getTotalPages());
            response.put("pageSize", userDtoPage.getSize());

            return ResponseEntity.ok(new ApiResponse("Users retrieved successfully", response));
        } catch (Exception e) {
            log.error("Error retrieving users", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error retrieving users", null));
        }
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user", description = "Retrieve the currently authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> getCurrentUser() {
        try {
            User user = userService.getAuthenticatedUser();
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.ok(new ApiResponse("Current user retrieved successfully", userDto));
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(UNAUTHORIZED).body(new ApiResponse(e.getMessage(), null));
        }
    }

    @PostMapping("/add")
    @Operation(summary = "Create new user", description = "Register a new user with USER role")
    public ResponseEntity<ApiResponse> createUser(@Valid @RequestBody CreateUserRequest request) {
        try {
            log.info("Creating new user with email: {}", request.getEmail());
            User user = userService.createUser(request);
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.status(CREATED).body(new ApiResponse("User created successfully!", userDto));
        } catch (AlreadyExistsException e) {
            log.warn("Attempt to create user with existing email: {}", request.getEmail());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error creating user", e);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse("Error creating user", null));
        }
    }

    @PostMapping("/admin/add")
    @Operation(summary = "Create admin user", description = "Create a new user with ADMIN role")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> createAdminUser(@Valid @RequestBody CreateUserRequest request) {
        try {
            log.info("Creating new admin user with email: {}", request.getEmail());
            User user = userService.createAdminUser(request);
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.status(CREATED).body(new ApiResponse("Admin user created successfully!", userDto));
        } catch (AlreadyExistsException e) {
            log.warn("Attempt to create admin user with existing email: {}", request.getEmail());
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error creating admin user", e);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse("Error creating admin user", null));
        }
    }

    @PutMapping("/{userId}")
    @Operation(summary = "Update user", description = "Update user information")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN') or @userService.getAuthenticatedUser().id == #userId")
    public ResponseEntity<ApiResponse> updateUser(
            @Valid @RequestBody UserUpdateRequest request,
            @PathVariable Long userId) {
        try {
            log.info("Updating user with ID: {}", userId);
            User user = userService.updateUser(request, userId);
            UserDto userDto = userService.convertUserToDto(user);
            return ResponseEntity.ok(new ApiResponse("User updated successfully!", userDto));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to update non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error updating user with ID: {}", userId, e);
            return ResponseEntity.status(BAD_REQUEST).body(new ApiResponse("Error updating user", null));
        }
    }

    @DeleteMapping("/{userId}")
    @Operation(summary = "Delete user", description = "Permanently delete a user")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> deleteUser(@PathVariable Long userId) {
        try {
            log.info("Deleting user with ID: {}", userId);
            userService.deleteUser(userId);
            return ResponseEntity.ok(new ApiResponse("User deleted successfully!", null));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to delete non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error deleting user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new ApiResponse("Error deleting user", null));
        }
    }

    @PatchMapping("/{userId}/deactivate")
    @Operation(summary = "Deactivate user", description = "Deactivate a user account (soft delete)")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> deactivateUser(@PathVariable Long userId) {
        try {
            log.info("Deactivating user with ID: {}", userId);
            userService.deactivateUser(userId);
            return ResponseEntity.ok(new ApiResponse("User deactivated successfully!", null));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to deactivate non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error deactivating user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new ApiResponse("Error deactivating user", null));
        }
    }

    @PatchMapping("/{userId}/activate")
    @Operation(summary = "Activate user", description = "Activate a previously deactivated user account")
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse> activateUser(@PathVariable Long userId) {
        try {
            log.info("Activating user with ID: {}", userId);
            userService.activateUser(userId);
            return ResponseEntity.ok(new ApiResponse("User activated successfully!", null));
        } catch (ResourceNotFoundException e) {
            log.warn("Attempt to activate non-existent user: {}", userId);
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(e.getMessage(), null));
        } catch (Exception e) {
            log.error("Error activating user with ID: {}", userId, e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new ApiResponse("Error activating user", null));
        }
    }

    @GetMapping("/check-email")
    @Operation(summary = "Check email availability", description = "Check if an email is already registered")
    public ResponseEntity<ApiResponse> checkEmailAvailability(@RequestParam String email) {
        try {
            boolean exists = userService.existsByEmail(email);
            Map<String, Object> response = new HashMap<>();
            response.put("email", email);
            response.put("available", !exists);

            return ResponseEntity.ok(new ApiResponse("Email availability checked", response));
        } catch (Exception e) {
            log.error("Error checking email availability", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error checking email availability", null));
        }
    }
}
