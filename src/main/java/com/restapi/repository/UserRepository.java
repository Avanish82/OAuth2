package com.restapi.repository;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.restapi.entity.UserEntity;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long>{
	
	//List<UserEntity> findByIdList(Long id);
	@Query(value = "SELECT * UserEntity WHERE findAll = 1", nativeQuery = true)
     public List<UserEntity> getUser(Long id);
	// public List<UserEntity> getMostFreshestFoods();
	
	//public UserEntity findByName(String name);
	
	public UserEntity findByName(String name);

}
