package com.GASB.account.model.repository;

import com.GASB.account.model.entity.Org;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrgRepo extends JpaRepository<Org,Long> {

}
