package com.exam.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.exam.dto.Member;
import com.exam.service.MemberService;

@Component
public class AuthProvider implements AuthenticationProvider {

	@Autowired
	MemberService memberService;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String userid = (String)authentication.getPrincipal();
		String passwd = (String)authentication.getCredentials();
		
		Member mem = memberService.findById(userid);
//		String encrptPw = mem.getPasswd();  // 없는 계정을 사용하면 mem이 null이기 때문에 NullPointerException 발생되기 때문에 사용안됨.
		
		//Authentication 하위클래스
		//로그인 성공시
		UsernamePasswordAuthenticationToken token = null;
		
		if(mem!=null && new BCryptPasswordEncoder().matches(passwd, mem.getPasswd())) { // 아이디가 있고 패스워드도 일치하면 (true이면)
			
			List<GrantedAuthority> list = new ArrayList<>();
			// ROLE 설정 시 사용됨.
			list.add(new SimpleGrantedAuthority("USER"));
			
			//암호화된 비번 대신에 raw 비번으로 설정
			mem.setPasswd(passwd);
			token = new UsernamePasswordAuthenticationToken(mem, null, list);
			return token;
		}
		//로그인 실패시
		throw new BadCredentialsException("비밀번호가 일치하지 않습니다. 다시 확인하세요.");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

}
