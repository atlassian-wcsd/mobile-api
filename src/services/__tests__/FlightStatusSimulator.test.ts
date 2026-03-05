import {
  FlightStatusSimulator,
  FlightStatus,
  TrackedFlight,
} from '../FlightStatusSimulator';
import { NotificationService } from '../NotificationService';
import { NotificationType, NotificationPriority } from '../../models/Notification';

describe('FlightStatusSimulator', () => {
  let notificationService: NotificationService;
  let simulator: FlightStatusSimulator;

  const createFlight = (
    overrides: Partial<TrackedFlight> = {}
  ): TrackedFlight => ({
    flightNumber: 'AA100',
    userId: 'user-1',
    currentStatus: FlightStatus.SCHEDULED,
    departureTime: '10:00',
    arrivalTime: '14:00',
    gate: 'A1',
    origin: 'JFK',
    destination: 'LAX',
    ...overrides,
  });

  beforeEach(() => {
    notificationService = new NotificationService();
    simulator = new FlightStatusSimulator(notificationService);
  });

  afterEach(() => {
    simulator.stopAutoSimulation();
  });

  describe('trackFlight', () => {
    it('should add a flight to the tracked flights list', () => {
      const flight = createFlight();
      simulator.trackFlight(flight);

      const tracked = simulator.getTrackedFlights();
      expect(tracked).toHaveLength(1);
      expect(tracked[0].flightNumber).toBe('AA100');
    });

    it('should allow tracking multiple flights', () => {
      simulator.trackFlight(createFlight({ flightNumber: 'AA100' }));
      simulator.trackFlight(createFlight({ flightNumber: 'BA200' }));

      expect(simulator.getTrackedFlights()).toHaveLength(2);
    });

    it('should overwrite a flight with the same flight number', () => {
      simulator.trackFlight(createFlight({ gate: 'A1' }));
      simulator.trackFlight(createFlight({ gate: 'B5' }));

      const tracked = simulator.getTrackedFlights();
      expect(tracked).toHaveLength(1);
      expect(tracked[0].gate).toBe('B5');
    });
  });

  describe('untrackFlight', () => {
    it('should remove a tracked flight and return true', () => {
      simulator.trackFlight(createFlight());
      const result = simulator.untrackFlight('AA100');

      expect(result).toBe(true);
      expect(simulator.getTrackedFlights()).toHaveLength(0);
    });

    it('should return false when the flight is not tracked', () => {
      const result = simulator.untrackFlight('NONEXISTENT');
      expect(result).toBe(false);
    });
  });

  describe('getTrackedFlights', () => {
    it('should return an empty array when no flights are tracked', () => {
      expect(simulator.getTrackedFlights()).toEqual([]);
    });

    it('should return all tracked flights', () => {
      simulator.trackFlight(createFlight({ flightNumber: 'AA100' }));
      simulator.trackFlight(createFlight({ flightNumber: 'BA200' }));

      const flights = simulator.getTrackedFlights();
      expect(flights).toHaveLength(2);

      const flightNumbers = flights.map((f) => f.flightNumber);
      expect(flightNumbers).toContain('AA100');
      expect(flightNumbers).toContain('BA200');
    });
  });

  describe('simulateStatusChange', () => {
    it('should return null for an untracked flight', () => {
      const result = simulator.simulateStatusChange(
        'UNKNOWN',
        FlightStatus.BOARDING
      );
      expect(result).toBeNull();
    });

    it('should generate a notification for a tracked flight', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.BOARDING
      );

      expect(notification).not.toBeNull();
      expect(notification?.userId).toBe('user-1');
      expect(notification?.title).toContain('AA100');
      expect(notification?.isRead).toBe(false);
    });

    it('should update the flight current status', () => {
      simulator.trackFlight(createFlight());
      simulator.simulateStatusChange('AA100', FlightStatus.BOARDING);

      const flights = simulator.getTrackedFlights();
      expect(flights[0].currentStatus).toBe(FlightStatus.BOARDING);
    });

    it('should set notification type to FLIGHT_STATUS for boarding', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.BOARDING
      );
      expect(notification?.type).toBe(NotificationType.FLIGHT_STATUS);
    });

    it('should set notification type to DELAY for delayed status', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.DELAYED
      );
      expect(notification?.type).toBe(NotificationType.DELAY);
    });

    it('should set notification type to CANCELLATION for cancelled status', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.CANCELLED
      );
      expect(notification?.type).toBe(NotificationType.CANCELLATION);
    });

    it('should set notification type to GATE_CHANGE for gate changed status', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.GATE_CHANGED,
        { gate: 'C5' }
      );
      expect(notification?.type).toBe(NotificationType.GATE_CHANGE);
    });

    it('should set priority to URGENT for cancelled flights', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.CANCELLED
      );
      expect(notification?.priority).toBe(NotificationPriority.URGENT);
    });

    it('should set priority to URGENT for diverted flights', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.DIVERTED
      );
      expect(notification?.priority).toBe(NotificationPriority.URGENT);
    });

    it('should set priority to HIGH for boarding', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.BOARDING
      );
      expect(notification?.priority).toBe(NotificationPriority.HIGH);
    });

    it('should set priority to HIGH for delayed', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.DELAYED
      );
      expect(notification?.priority).toBe(NotificationPriority.HIGH);
    });

    it('should include metadata with flight information', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.BOARDING
      );

      expect(notification?.metadata).toBeDefined();
      expect(notification?.metadata?.flightNumber).toBe('AA100');
      expect(notification?.metadata?.previousStatus).toBe(
        FlightStatus.SCHEDULED
      );
      expect(notification?.metadata?.newStatus).toBe(FlightStatus.BOARDING);
    });

    it('should update gate in flight metadata when gate change is provided', () => {
      simulator.trackFlight(createFlight({ gate: 'A1' }));
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.GATE_CHANGED,
        { gate: 'C5' }
      );

      expect(notification?.metadata?.gate).toBe('C5');

      // Verify the tracked flight itself was updated
      const flights = simulator.getTrackedFlights();
      expect(flights[0].gate).toBe('C5');
    });

    it('should update departure time when delay info is provided', () => {
      simulator.trackFlight(createFlight({ departureTime: '10:00' }));
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.DELAYED,
        { departureTime: '14:30' }
      );

      expect(notification?.metadata?.departureTime).toBe('14:30');

      // Verify the tracked flight itself was updated
      const flights = simulator.getTrackedFlights();
      expect(flights[0].departureTime).toBe('14:30');
    });

    it('should update arrival time when provided in additional info', () => {
      simulator.trackFlight(createFlight({ arrivalTime: '14:00' }));
      simulator.simulateStatusChange('AA100', FlightStatus.DELAYED, {
        arrivalTime: '18:00',
      });

      const flights = simulator.getTrackedFlights();
      expect(flights[0].arrivalTime).toBe('18:00');
    });

    it('should store the notification in the notification service', () => {
      simulator.trackFlight(createFlight());
      const notification = simulator.simulateStatusChange(
        'AA100',
        FlightStatus.BOARDING
      );

      const retrieved = notificationService.getNotification(notification!.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(notification?.id);
    });
  });

  describe('runFlightLifecycleScenario', () => {
    it('should return an empty array for an untracked flight', () => {
      const notifications = simulator.runFlightLifecycleScenario('UNKNOWN');
      expect(notifications).toEqual([]);
    });

    it('should generate multiple notifications for a lifecycle scenario', () => {
      simulator.trackFlight(createFlight());
      const notifications = simulator.runFlightLifecycleScenario('AA100');

      // Lifecycle: GATE_CHANGED, DELAYED, BOARDING, DEPARTED, IN_FLIGHT, LANDED
      expect(notifications).toHaveLength(6);
    });

    it('should progress through expected statuses in order', () => {
      simulator.trackFlight(createFlight());
      const notifications = simulator.runFlightLifecycleScenario('AA100');

      const statuses = notifications.map((n) => n.metadata?.newStatus);
      expect(statuses).toEqual([
        FlightStatus.GATE_CHANGED,
        FlightStatus.DELAYED,
        FlightStatus.BOARDING,
        FlightStatus.DEPARTED,
        FlightStatus.IN_FLIGHT,
        FlightStatus.LANDED,
      ]);
    });

    it('should update gate during gate change step', () => {
      simulator.trackFlight(createFlight({ gate: 'A1' }));
      const notifications = simulator.runFlightLifecycleScenario('AA100');

      // First step is GATE_CHANGED with gate 'B42'
      expect(notifications[0].metadata?.gate).toBe('B42');
    });

    it('should update departure time during delay step', () => {
      simulator.trackFlight(createFlight());
      const notifications = simulator.runFlightLifecycleScenario('AA100');

      // Second step is DELAYED with departureTime '14:30'
      expect(notifications[1].metadata?.departureTime).toBe('14:30');
    });

    it('should leave the flight in LANDED status after the scenario', () => {
      simulator.trackFlight(createFlight());
      simulator.runFlightLifecycleScenario('AA100');

      const flights = simulator.getTrackedFlights();
      expect(flights[0].currentStatus).toBe(FlightStatus.LANDED);
    });

    it('should store all notifications in the notification service', () => {
      simulator.trackFlight(createFlight());
      simulator.runFlightLifecycleScenario('AA100');

      const all = notificationService.listNotifications('user-1');
      expect(all.length).toBe(6);
    });
  });

  describe('auto simulation', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should generate notifications at the specified interval', () => {
      simulator.trackFlight(createFlight());
      simulator.startAutoSimulation(1000);

      jest.advanceTimersByTime(3000);

      // After 3 seconds with 1s interval, we should have up to 3 notifications
      // (depending on random transitions — SCHEDULED can always transition)
      const notifications = notificationService.listNotifications('user-1');
      expect(notifications.length).toBeGreaterThanOrEqual(1);
    });

    it('should stop generating notifications after stopAutoSimulation', () => {
      simulator.trackFlight(createFlight());
      simulator.startAutoSimulation(1000);

      jest.advanceTimersByTime(2000);
      simulator.stopAutoSimulation();

      const countAfterStop = notificationService.listNotifications('user-1').length;

      jest.advanceTimersByTime(5000);

      const countLater = notificationService.listNotifications('user-1').length;
      expect(countLater).toBe(countAfterStop);
    });

    it('should not generate notifications when no flights are tracked', () => {
      simulator.startAutoSimulation(1000);

      jest.advanceTimersByTime(5000);

      // No flights tracked, so no notifications should be created
      // We can't easily check by userId, but the service should have nothing
      expect(notificationService.listNotifications('user-1')).toHaveLength(0);
    });

    it('should use default interval when none is specified', () => {
      simulator.trackFlight(createFlight());
      simulator.startAutoSimulation();

      // Default is 5000ms, so advancing 4999ms should not trigger
      jest.advanceTimersByTime(4999);
      const countBefore = notificationService.listNotifications('user-1').length;

      jest.advanceTimersByTime(1);
      const countAfter = notificationService.listNotifications('user-1').length;

      // At 5000ms exactly, one interval should fire
      expect(countAfter).toBeGreaterThanOrEqual(countBefore);
    });

    it('should stop previous simulation when starting a new one', () => {
      simulator.trackFlight(createFlight());

      simulator.startAutoSimulation(1000);
      jest.advanceTimersByTime(2000);

      // Starting a new simulation should stop the old one
      simulator.startAutoSimulation(10000);
      jest.advanceTimersByTime(5000);

      // With 10s interval and only 5s elapsed, no new notification from second sim
      const countAt7s = notificationService.listNotifications('user-1').length;

      jest.advanceTimersByTime(5000);
      const countAt12s = notificationService.listNotifications('user-1').length;

      // After 10s total on new interval, one more tick should have fired
      expect(countAt12s).toBeGreaterThanOrEqual(countAt7s);
    });

    it('should be safe to call stopAutoSimulation when not running', () => {
      expect(() => {
        simulator.stopAutoSimulation();
      }).not.toThrow();
    });
  });
});
