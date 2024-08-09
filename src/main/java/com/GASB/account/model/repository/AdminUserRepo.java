package com.GASB.account.model.repository;

import com.GASB.account.model.entity.AdminUsers;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminUserRepo extends JpaRepository<AdminUsers, Long> {
    @Query("SELECT a FROM AdminUsers a WHERE a.email = :email")
    AdminUsers findByEmail(@Param("email") String email);

    boolean existsByEmail(String email);
}
