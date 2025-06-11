package com.figrclub.figrclubdb.repository;

import com.figrclub.figrclubdb.domain.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Verifica si existe un usuario con el email dado
     */
    boolean existsByEmail(String email);

    /**
     * Encuentra un usuario por su email
     */
    User findByEmail(String email);

    /**
     * Encuentra un usuario por email (Optional)
     */
    Optional<User> findOptionalByEmail(String email);

    /**
     * Encuentra todos los usuarios activos
     */
    Page<User> findByIsEnabledTrue(Pageable pageable);

    /**
     * Encuentra todos los usuarios inactivos
     */
    Page<User> findByIsEnabledFalse(Pageable pageable);

    /**
     * Busca usuarios por nombre o apellido (case insensitive)
     */
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<User> findByNameContainingIgnoreCase(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Encuentra usuarios por rol
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Page<User> findByRoleName(@Param("roleName") String roleName, Pageable pageable);

    /**
     * Encuentra usuarios creados después de una fecha específica
     */
    @Query("SELECT u FROM User u WHERE u.createdAt >= :date")
    List<User> findUsersCreatedAfter(@Param("date") LocalDateTime date);

    /**
     * Cuenta usuarios activos
     */
    long countByIsEnabledTrue();

    /**
     * Cuenta usuarios por rol
     */
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = :roleName")
    long countByRoleName(@Param("roleName") String roleName);
}
