package sslCertificationLibrary.utilities;

import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.Temporal;

/**
 * @author Marcelo d'Almeida
 */

public class Util 
{	
	public static void printDelimiter()
	{
		System.out.println();
        System.out.println("################################################################");
        System.out.println();
	}
	
	public static void showTimeDifference(Temporal dateTime, Temporal referenceDateTime)
	{
		ZonedDateTime tempDateTime = ZonedDateTime.from(dateTime);

		long years = tempDateTime.until(referenceDateTime, ChronoUnit.YEARS);
		tempDateTime = tempDateTime.plusYears(years);

		long months = tempDateTime.until(referenceDateTime, ChronoUnit.MONTHS);
		tempDateTime = tempDateTime.plusMonths(months);

		long days = tempDateTime.until(referenceDateTime, ChronoUnit.DAYS);
		tempDateTime = tempDateTime.plusDays(days);

		long hours = tempDateTime.until(referenceDateTime, ChronoUnit.HOURS);
		tempDateTime = tempDateTime.plusHours(hours);

		long minutes = tempDateTime.until(referenceDateTime, ChronoUnit.MINUTES);
		tempDateTime = tempDateTime.plusMinutes(minutes);

		long seconds = tempDateTime.until(referenceDateTime, ChronoUnit.SECONDS);
		
		
		if (years != 0)
		{
			System.out.print(years);
			if (years == 1)
			{
				System.out.print(" year ");
			}
			else
			{
				System.out.print(" years ");
			}
		}
		if (months != 0)
		{
			System.out.print(months);
			if (months == 1)
			{
				System.out.print(" month ");
			}
			else
			{
				System.out.print(" months ");
			}
		}
		if (days != 0)
		{
			System.out.print(days);
			if (days == 1)
			{
				System.out.print(" day ");
			}
			else
			{
				System.out.print(" days ");
			}
		}
		if (hours != 0)
		{
			System.out.print(hours);
			if (hours == 1)
			{
				System.out.print(" hour ");
			}
			else
			{
				System.out.print(" hours ");
			}
		}
		if (minutes != 0)
		{
			System.out.print(minutes);
			if (minutes == 1)
			{
				System.out.print(" minute ");
			}
			else
			{
				System.out.print(" minutes ");
			}
		}
		if (seconds != 0)
		{
			System.out.print(seconds);
			if (seconds == 1)
			{
				System.out.print(" second ");
			}
			else
			{
				System.out.print(" seconds ");
			}
		}
		System.out.println();
	}
}
