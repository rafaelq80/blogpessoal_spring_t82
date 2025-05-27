package com.generation.blogpessoal.util;

import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.model.UsuarioLogin;

public class TestBuilder {

	public static Usuario criarUsuario(Long id, String nome, String email, String senha) {
		Usuario usuario = new Usuario();
		usuario.setId(id);
		usuario.setNome(nome);
		usuario.setUsuario(email);
		usuario.setSenha(senha);
		usuario.setFoto("-");
		return usuario;
	}
	
	public static UsuarioLogin criarUsuarioLogin(String email, String senha) {
        UsuarioLogin usuarioLogin = new UsuarioLogin();
        usuarioLogin.setId(null);
        usuarioLogin.setNome("");
        usuarioLogin.setUsuario(email);
        usuarioLogin.setSenha(senha);
        usuarioLogin.setFoto("");
        usuarioLogin.setToken("");
        return usuarioLogin;
    }
	
	public static Usuario criarUsuarioRoot() {
		return criarUsuario(null, "Root", "root@email.com", "rootroot");
	}
	
}
