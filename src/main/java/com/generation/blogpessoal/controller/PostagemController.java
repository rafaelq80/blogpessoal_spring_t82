package com.generation.blogpessoal.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.generation.blogpessoal.model.Postagem;
import com.generation.blogpessoal.repository.PostagemRepository;
import com.generation.blogpessoal.repository.TemaRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/postagens")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PostagemController {

	@Autowired
	private PostagemRepository postagemRepository;

	@Autowired
	private TemaRepository temaRepository;

	@GetMapping
	public ResponseEntity<List<Postagem>> getAll() {

		/**
		 * O Método executará a consulta: SELECT * FROM tb_postagens;
		 */
		return ResponseEntity.ok(postagemRepository.findAll());

	}

	@GetMapping("/{id}")
	public ResponseEntity<Postagem> getById(@PathVariable Long id) {

		/**
		 * O Método executará a consulta: SELECT * FROM tb_postagens WHERE id = ?; A
		 * interrogação representa o valor inserido no parâmetro id do método getById
		 */
		return postagemRepository.findById(id).map(resposta -> ResponseEntity.ok(resposta))
				.orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
	}

	@GetMapping("/titulo/{titulo}")
	public ResponseEntity<List<Postagem>> getAllByTitulo(@PathVariable String titulo) {

		/**
		 * O Método executará a consulta: SELECT * FROM tb_postagens WHERE titulo LIKE
		 * '%?%"; A interrogação representa o valor inserido no parâmetro titulo do
		 * método getAllByTitulo
		 */
		return ResponseEntity.ok(postagemRepository.findAllByTituloContainingIgnoreCase(titulo));

	}

	@PostMapping
	public ResponseEntity<Postagem> post(@Valid @RequestBody Postagem postagem) {

		/** 
		 * Verifica se o tema existe antes de persistir a postagem no Banco de dados
		 * */
		if (temaRepository.existsById(postagem.getTema().getId())) {

			/**
			 * O Método executará a consulta: INSERT INTO tb_postagens VALUES (titulo,
			 * texto, data) VALUES (?, ?, ?); As interrogações representam os valores
			 * inseridos nos respectivos atributos do objeto postagem, parâmetro do método
			 * post.
			 */
			return ResponseEntity.status(HttpStatus.CREATED).body(postagemRepository.save(postagem));
		}
		
		/** 
		 * Caso o tema não exista, retorna um Bad Request informando que o tema não existe
		 * */
		throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "O Tema não existe!", null);
	}

	@PutMapping
	public ResponseEntity<Postagem> put(@Valid @RequestBody Postagem postagem) {

		/**
		 * Verifica se o id é nulo. Se for nulo, retorna o HTTP Status 400 - BAD_REQUEST
		 */
		if (postagem.getId() == null)
			return ResponseEntity.badRequest().build();

		/**
		 * Antes de atualizar, verifica se a postagem existe. Se existir, atualiza
		 */
		if (postagemRepository.existsById(postagem.getId())) {
			
			/** 
			 * Verifica se o tema existe antes de atualizar a postagem no Banco de dados
			 * */
			if (temaRepository.existsById(postagem.getTema().getId()))
				/**
				 * O Método executará a consulta: UPDATE tb_postagens SET titulo = ?, texto = ?,
				 * data = ? WHERE id = ?; As interrogações representam os valores inseridos nos
				 * respectivos atributos do objeto postagem, parâmetro do método post.
				 */
				return ResponseEntity.status(HttpStatus.OK).body(postagemRepository.save(postagem));
		
			/** 
			 * Caso o tema não exista, retorna um Bad Request informando que o tema não existe
			 * */
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "O Tema não existe!", null);
			
		}
		/**
		 * Se a postagem não existir, retorna o HTTP Status 404 - NOT_FOUND
		 */
		return ResponseEntity.status(HttpStatus.NOT_FOUND).build();

	}

	@DeleteMapping("/{id}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void delete(@PathVariable Long id) {

		/**
		 * Busca a postagem pelo id e guarda o resultado no Optional postagem
		 */
		Optional<Postagem> postagem = postagemRepository.findById(id);

		/**
		 * Verifica se o Optional postagem está vazio. Se estiver vazio, retorna o HTTP
		 * Status 404 - NOT_FOUND
		 */
		if (postagem.isEmpty())
			throw new ResponseStatusException(HttpStatus.NOT_FOUND);

		/**
		 * Caso contrário, o Método executará a consulta: DELETE FROM tb_postagens WHERE
		 * id = ?; A interrogação representa parâmetro id do método delete.
		 */
		postagemRepository.deleteById(id);

	}
}
