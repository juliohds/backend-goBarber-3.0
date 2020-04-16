import Appointment from '../models/Appointments';
import { isEqual } from 'date-fns';

interface CreateAppointmentDTO {
  provider: string;
  date: Date;
}

class AppointmentsRepository {
  private appointments:  Appointment[];

  constructor() {
    this.appointments = [];
  }

  public all() : Appointment[]{
    return this.appointments;
  }

  public findByDate(date: Date):Appointment | null {
    const findAppointment = this.appointments.find(appointment =>
      isEqual(date, appointment.date),
    );
    return findAppointment || null;
  }

  public create({ provider, date}: CreateAppointmentDTO){
    const appointment = new Appointment({provider, date});

    this.appointments.push(appointment);
    return this.appointments;
  }
}

export default AppointmentsRepository;
