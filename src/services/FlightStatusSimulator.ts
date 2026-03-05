import { NotificationService } from './NotificationService';
import {
  NotificationType,
  NotificationPriority,
  Notification,
} from '../models/Notification';

/**
 * Enum representing possible flight statuses
 */
export enum FlightStatus {
  SCHEDULED = 'SCHEDULED',
  BOARDING = 'BOARDING',
  DEPARTED = 'DEPARTED',
  IN_FLIGHT = 'IN_FLIGHT',
  LANDED = 'LANDED',
  DELAYED = 'DELAYED',
  CANCELLED = 'CANCELLED',
  DIVERTED = 'DIVERTED',
  GATE_CHANGED = 'GATE_CHANGED',
}

/**
 * Interface representing a tracked flight
 */
export interface TrackedFlight {
  flightNumber: string;
  userId: string;
  currentStatus: FlightStatus;
  departureTime: string;
  arrivalTime: string;
  gate: string;
  origin: string;
  destination: string;
}

/**
 * Configuration for notification priority mapping
 */
const STATUS_PRIORITY_MAP: Record<FlightStatus, NotificationPriority> = {
  [FlightStatus.SCHEDULED]: NotificationPriority.LOW,
  [FlightStatus.BOARDING]: NotificationPriority.HIGH,
  [FlightStatus.DEPARTED]: NotificationPriority.MEDIUM,
  [FlightStatus.IN_FLIGHT]: NotificationPriority.LOW,
  [FlightStatus.LANDED]: NotificationPriority.MEDIUM,
  [FlightStatus.DELAYED]: NotificationPriority.HIGH,
  [FlightStatus.CANCELLED]: NotificationPriority.URGENT,
  [FlightStatus.DIVERTED]: NotificationPriority.URGENT,
  [FlightStatus.GATE_CHANGED]: NotificationPriority.HIGH,
};

/**
 * Configuration for notification type mapping
 */
const STATUS_NOTIFICATION_TYPE_MAP: Record<FlightStatus, NotificationType> = {
  [FlightStatus.SCHEDULED]: NotificationType.FLIGHT_STATUS,
  [FlightStatus.BOARDING]: NotificationType.FLIGHT_STATUS,
  [FlightStatus.DEPARTED]: NotificationType.FLIGHT_STATUS,
  [FlightStatus.IN_FLIGHT]: NotificationType.FLIGHT_STATUS,
  [FlightStatus.LANDED]: NotificationType.FLIGHT_STATUS,
  [FlightStatus.DELAYED]: NotificationType.DELAY,
  [FlightStatus.CANCELLED]: NotificationType.CANCELLATION,
  [FlightStatus.DIVERTED]: NotificationType.FLIGHT_STATUS,
  [FlightStatus.GATE_CHANGED]: NotificationType.GATE_CHANGE,
};

/**
 * Simulator that generates notifications based on flight status changes.
 * Used to demonstrate the notification system with realistic travel scenarios.
 */
export class FlightStatusSimulator {
  private notificationService: NotificationService;
  private trackedFlights: Map<string, TrackedFlight> = new Map();
  private simulationIntervalId: ReturnType<typeof setInterval> | null = null;

  constructor(notificationService: NotificationService) {
    this.notificationService = notificationService;
  }

  /**
   * Add a flight to be tracked for status changes
   * @param flight - The flight to track
   */
  public trackFlight(flight: TrackedFlight): void {
    this.trackedFlights.set(flight.flightNumber, flight);
  }

  /**
   * Remove a flight from tracking
   * @param flightNumber - The flight number to stop tracking
   * @returns true if the flight was removed, false if not found
   */
  public untrackFlight(flightNumber: string): boolean {
    return this.trackedFlights.delete(flightNumber);
  }

  /**
   * Get all currently tracked flights
   * @returns Array of tracked flights
   */
  public getTrackedFlights(): TrackedFlight[] {
    return Array.from(this.trackedFlights.values());
  }

  /**
   * Simulate a flight status change and generate a notification
   * @param flightNumber - The flight number to update
   * @param newStatus - The new flight status
   * @param additionalInfo - Optional additional info (e.g., new gate, new time)
   * @returns The generated notification, or null if the flight is not tracked
   */
  public simulateStatusChange(
    flightNumber: string,
    newStatus: FlightStatus,
    additionalInfo?: { gate?: string; departureTime?: string; arrivalTime?: string }
  ): Notification | null {
    const flight = this.trackedFlights.get(flightNumber);
    if (!flight) return null;

    const previousStatus = flight.currentStatus;
    flight.currentStatus = newStatus;

    if (additionalInfo?.gate) {
      flight.gate = additionalInfo.gate;
    }
    if (additionalInfo?.departureTime) {
      flight.departureTime = additionalInfo.departureTime;
    }
    if (additionalInfo?.arrivalTime) {
      flight.arrivalTime = additionalInfo.arrivalTime;
    }

    this.trackedFlights.set(flightNumber, flight);

    const title = this.buildNotificationTitle(flight, newStatus);
    const message = this.buildNotificationMessage(
      flight,
      previousStatus,
      newStatus,
      additionalInfo
    );

    return this.notificationService.createNotification({
      userId: flight.userId,
      title,
      message,
      type: STATUS_NOTIFICATION_TYPE_MAP[newStatus],
      priority: STATUS_PRIORITY_MAP[newStatus],
      metadata: {
        flightNumber: flight.flightNumber,
        previousStatus,
        newStatus,
        gate: flight.gate,
        departureTime: flight.departureTime,
        arrivalTime: flight.arrivalTime,
      },
    });
  }

  /**
   * Start an automatic simulation that randomly changes flight statuses
   * at the given interval. Useful for demos and testing.
   * @param intervalMs - Interval in milliseconds between status changes
   */
  public startAutoSimulation(intervalMs: number = 5000): void {
    if (this.simulationIntervalId !== null) {
      this.stopAutoSimulation();
    }

    this.simulationIntervalId = setInterval(() => {
      const flights = this.getTrackedFlights();
      if (flights.length === 0) return;

      const randomFlight = flights[Math.floor(Math.random() * flights.length)];
      const nextStatus = this.getNextRealisticStatus(
        randomFlight.currentStatus
      );

      if (nextStatus) {
        const additionalInfo = this.generateAdditionalInfo(nextStatus);
        this.simulateStatusChange(
          randomFlight.flightNumber,
          nextStatus,
          additionalInfo
        );
      }
    }, intervalMs);
  }

  /**
   * Stop the automatic simulation
   */
  public stopAutoSimulation(): void {
    if (this.simulationIntervalId !== null) {
      clearInterval(this.simulationIntervalId);
      this.simulationIntervalId = null;
    }
  }

  /**
   * Run a predefined scenario that simulates a typical flight lifecycle
   * @param flightNumber - The flight number to simulate
   * @returns Array of generated notifications
   */
  public runFlightLifecycleScenario(
    flightNumber: string
  ): Notification[] {
    const flight = this.trackedFlights.get(flightNumber);
    if (!flight) return [];

    const notifications: Notification[] = [];
    const scenario: Array<{
      status: FlightStatus;
      additionalInfo?: { gate?: string; departureTime?: string; arrivalTime?: string };
    }> = [
      { status: FlightStatus.GATE_CHANGED, additionalInfo: { gate: 'B42' } },
      { status: FlightStatus.DELAYED, additionalInfo: { departureTime: '14:30' } },
      { status: FlightStatus.BOARDING },
      { status: FlightStatus.DEPARTED },
      { status: FlightStatus.IN_FLIGHT },
      { status: FlightStatus.LANDED },
    ];

    for (const step of scenario) {
      const notification = this.simulateStatusChange(
        flightNumber,
        step.status,
        step.additionalInfo
      );
      if (notification) {
        notifications.push(notification);
      }
    }

    return notifications;
  }

  /**
   * Build a concise notification title based on flight and status
   */
  private buildNotificationTitle(
    flight: TrackedFlight,
    newStatus: FlightStatus
  ): string {
    const statusTitleMap: Record<FlightStatus, string> = {
      [FlightStatus.SCHEDULED]: `Flight ${flight.flightNumber} Scheduled`,
      [FlightStatus.BOARDING]: `Flight ${flight.flightNumber} Now Boarding`,
      [FlightStatus.DEPARTED]: `Flight ${flight.flightNumber} Has Departed`,
      [FlightStatus.IN_FLIGHT]: `Flight ${flight.flightNumber} In Flight`,
      [FlightStatus.LANDED]: `Flight ${flight.flightNumber} Has Landed`,
      [FlightStatus.DELAYED]: `Flight ${flight.flightNumber} Delayed`,
      [FlightStatus.CANCELLED]: `Flight ${flight.flightNumber} Cancelled`,
      [FlightStatus.DIVERTED]: `Flight ${flight.flightNumber} Diverted`,
      [FlightStatus.GATE_CHANGED]: `Flight ${flight.flightNumber} Gate Changed`,
    };

    return statusTitleMap[newStatus];
  }

  /**
   * Build a detailed notification message
   */
  private buildNotificationMessage(
    flight: TrackedFlight,
    previousStatus: FlightStatus,
    newStatus: FlightStatus,
    additionalInfo?: { gate?: string; departureTime?: string; arrivalTime?: string }
  ): string {
    const base = `Flight ${flight.flightNumber} (${flight.origin} → ${flight.destination})`;

    switch (newStatus) {
      case FlightStatus.BOARDING:
        return `${base} is now boarding at gate ${flight.gate}. Please proceed to the gate.`;
      case FlightStatus.DELAYED:
        return `${base} has been delayed. New departure time: ${additionalInfo?.departureTime ?? flight.departureTime}.`;
      case FlightStatus.CANCELLED:
        return `${base} has been cancelled. Please contact the airline for rebooking options.`;
      case FlightStatus.GATE_CHANGED:
        return `${base} gate has changed to ${additionalInfo?.gate ?? flight.gate}. Please proceed to the new gate.`;
      case FlightStatus.DEPARTED:
        return `${base} has departed. Estimated arrival: ${flight.arrivalTime}.`;
      case FlightStatus.LANDED:
        return `${base} has landed at ${flight.destination}. Welcome to your destination!`;
      case FlightStatus.IN_FLIGHT:
        return `${base} is currently in flight. Estimated arrival: ${flight.arrivalTime}.`;
      case FlightStatus.DIVERTED:
        return `${base} has been diverted. Please check with the airline for updated information.`;
      case FlightStatus.SCHEDULED:
        return `${base} is scheduled to depart at ${flight.departureTime} from gate ${flight.gate}.`;
      default:
        return `${base} status changed from ${previousStatus} to ${newStatus}.`;
    }
  }

  /**
   * Get the next realistic status in a flight lifecycle
   */
  private getNextRealisticStatus(
    currentStatus: FlightStatus
  ): FlightStatus | null {
    const transitionMap: Record<FlightStatus, FlightStatus[]> = {
      [FlightStatus.SCHEDULED]: [
        FlightStatus.BOARDING,
        FlightStatus.DELAYED,
        FlightStatus.GATE_CHANGED,
        FlightStatus.CANCELLED,
      ],
      [FlightStatus.GATE_CHANGED]: [
        FlightStatus.BOARDING,
        FlightStatus.DELAYED,
      ],
      [FlightStatus.DELAYED]: [
        FlightStatus.BOARDING,
        FlightStatus.CANCELLED,
      ],
      [FlightStatus.BOARDING]: [FlightStatus.DEPARTED],
      [FlightStatus.DEPARTED]: [FlightStatus.IN_FLIGHT],
      [FlightStatus.IN_FLIGHT]: [
        FlightStatus.LANDED,
        FlightStatus.DIVERTED,
      ],
      [FlightStatus.LANDED]: [],
      [FlightStatus.CANCELLED]: [],
      [FlightStatus.DIVERTED]: [FlightStatus.LANDED],
    };

    const possibleTransitions = transitionMap[currentStatus] ?? [];
    if (possibleTransitions.length === 0) return null;

    return possibleTransitions[
      Math.floor(Math.random() * possibleTransitions.length)
    ];
  }

  /**
   * Generate realistic additional info for certain status changes
   */
  private generateAdditionalInfo(
    status: FlightStatus
  ): { gate?: string; departureTime?: string } | undefined {
    if (status === FlightStatus.GATE_CHANGED) {
      const gates = ['A1', 'A12', 'B3', 'B22', 'C7', 'C15', 'D4', 'D18'];
      return { gate: gates[Math.floor(Math.random() * gates.length)] };
    }

    if (status === FlightStatus.DELAYED) {
      const hour = 12 + Math.floor(Math.random() * 10);
      const minute = Math.floor(Math.random() * 60)
        .toString()
        .padStart(2, '0');
      return { departureTime: `${hour}:${minute}` };
    }

    return undefined;
  }
}
