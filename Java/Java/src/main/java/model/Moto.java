package model;

	import jakarta.persistence.*;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;
	import java.time.LocalDateTime;

import io.swagger.v3.oas.annotations.media.Schema;

	@Entity
	@Table(name = "moto")
	public class Moto {

	    @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;

	    @Schema(description = "Número da placa da moto", example = "ABC-1234")
	    @Size(max = 10)
	    private String placa;

	    @Size(max = 17)
	    private String chassi;

	    @Size(max = 15)
	    private String motor;

	    @Enumerated(EnumType.STRING)
	    private StatusMoto status;

	    private String localizacao;

	    @PastOrPresent(message = "Data de check-in não pode estar no futuro")
	    private LocalDate dataCheckin;

	    private LocalDateTime dataCheckout;

	    @ManyToOne
	    @JoinColumn(name = "filial_id")
	    private Filial filial;

		/**
		 * @return the id
		 */
		public Long getId() {
			return id;
		}

		/**
		 * @param id the id to set
		 */
		public void setId(Long id) {
			this.id = id;
		}

		/**
		 * @return the placa
		 */
		public String getPlaca() {
			return placa;
		}

		/**
		 * @param placa the placa to set
		 */
		public void setPlaca(String placa) {
			this.placa = placa;
		}

		/**
		 * @return the chassi
		 */
		public String getChassi() {
			return chassi;
		}

		/**
		 * @param chassi the chassi to set
		 */
		public void setChassi(String chassi) {
			this.chassi = chassi;
		}

		/**
		 * @return the motor
		 */
		public String getMotor() {
			return motor;
		}

		/**
		 * @param motor the motor to set
		 */
		public void setMotor(String motor) {
			this.motor = motor;
		}

		/**
		 * @return the status
		 */
		public StatusMoto getStatus() {
			return status;
		}

		/**
		 * @param status the status to set
		 */
		public void setStatus(StatusMoto status) {
			this.status = status;
		}

		/**
		 * @return the localizacao
		 */
		public String getLocalizacao() {
			return localizacao;
		}

		/**
		 * @param localizacao the localizacao to set
		 */
		public void setLocalizacao(String localizacao) {
			this.localizacao = localizacao;
		}

		/**
		 * @return the dataCheckin
		 */
		public LocalDate getDataCheckin() {
			return dataCheckin;
		}

		/**
		 * @param dataCheckin the dataCheckin to set
		 */
		public void setDataCheckin(LocalDate dataCheckin) {
			this.dataCheckin = dataCheckin;
		}

		/**
		 * @return the dataCheckout
		 */
		public LocalDateTime getDataCheckout() {
			return dataCheckout;
		}

		/**
		 * @param dataCheckout the dataCheckout to set
		 */
		public void setDataCheckout(LocalDateTime dataCheckout) {
			this.dataCheckout = dataCheckout;
		}

		/**
		 * @return the filial
		 */
		public Filial getFilial() {
			return filial;
		}

		/**
		 * @param filial the filial to set
		 */
		public void setFilial(Filial filial) {
			this.filial = filial;
		}

	    
	}