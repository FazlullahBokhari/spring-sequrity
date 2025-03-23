package com.faiz.repository;

import com.faiz.entities.Role;
import com.faiz.entities.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(RoleType roleType);
}
