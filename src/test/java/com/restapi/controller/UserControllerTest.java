package com.restapi.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc; 
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.restapi.entity.UserEntity;
import com.restapi.service.UserService;

//@RunWith(SpringJUnit4ClassRunner.class)
@RunWith(MockitoJUnitRunner.class)
class UserControllerTest {

    private MockMvc mockMvc;
	
	@InjectMocks
	private UserController userController;
	
	@Mock
	@Autowired
	private UserService userSer;
	
	
	@Before
	public void setUp()throws Exception{
		mockMvc = MockMvcBuilders.standaloneSetup(userController)
				.build();
	}
	
	@AfterAll
	static void tearDownAfterClass() throws Exception {
		
	}

	@Test
	public void testWelcomePublic() throws Exception {
		mockMvc.perform(get("/public"))
		   .andExpect(status().isOk())
		.andExpect(status().isOk())
		.andExpect(content().string("welcome public/guest user"));
	}

	 

	@Test
	public void testWelcomeAdmin() throws Exception {
		mockMvc.perform(
				get("/admin")   
			)
			.andExpect(status().isOk())
			.andExpect(content().string("welcome admin"));
	}

	@Test
	void testWelcomeUser() {
		fail("Not yet implemented");
	}

	@Test
	void testAddUser() {
		fail("Not yet implemented");
	}

	@Test
    public void testGetUser() {
		//Give
       List<UserEntity> users = new ArrayList<UserEntity>();
       users.add(new UserEntity(1L, "kumar", "india", 88888888));
       users.add(new UserEntity(2L, "Alok kumar", "NEPAL", 99999999));
       
       //when //then
       when(userSer.getUser()).thenReturn(users);
       
       //Assert test
       List<UserEntity> users2 = userController.getUser();
       assertEquals(2, users2.size());
       verify(userSer, times(1)).getUser();
       
       
       
       
       
       
       
       
       
       
       
       
		
		
		//fail("Not yet implemented");
	}

	@Test
	void testGetUserById() {
		fail("Not yet implemented");
	}

	@Test
	void testUpdateUser() {
		fail("Not yet implemented");
	}

	@Test
	void testDeleteById() {
		fail("Not yet implemented");
	}

}
