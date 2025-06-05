import {
  TrustedContact as PrismaTrustedContact,
  TrustedContactStatus as PrismaTrustedContactStatus,
} from '@prisma/client';
import { TrustedContact, TrustedContactStatus } from '../models/trusted-contact.model';

/**
 * Maps a Prisma trusted contact to a domain trusted contact
 * @param prismaContact The Prisma trusted contact
 * @returns The domain trusted contact or null if not provided
 */
export function mapToDomainTrustedContact(
  prismaContact: PrismaTrustedContact | null
): TrustedContact | null {
  if (!prismaContact) return null;

  // Map Prisma enum to domain enum
  let status: TrustedContactStatus;
  switch (prismaContact.status) {
    case PrismaTrustedContactStatus.PENDING:
      status = TrustedContactStatus.PENDING;
      break;
    case PrismaTrustedContactStatus.ACTIVE:
      status = TrustedContactStatus.ACTIVE;
      break;
    case PrismaTrustedContactStatus.REVOKED:
      status = TrustedContactStatus.REVOKED;
      break;
    default:
      status = TrustedContactStatus.PENDING;
  }

  return {
    id: prismaContact.id,
    userId: prismaContact.userId,
    name: prismaContact.name,
    email: prismaContact.email,
    phone: prismaContact.phone,
    relationship: prismaContact.relationship,
    status,
    createdAt: prismaContact.createdAt,
    updatedAt: prismaContact.updatedAt,
    verifiedAt: prismaContact.verifiedAt,
  };
}

/**
 * Maps a domain trusted contact status to a Prisma trusted contact status
 * @param status The domain status
 * @returns The Prisma status
 */
export function mapToPrismaStatus(status: TrustedContactStatus): PrismaTrustedContactStatus {
  switch (status) {
    case TrustedContactStatus.PENDING:
      return PrismaTrustedContactStatus.PENDING;
    case TrustedContactStatus.ACTIVE:
      return PrismaTrustedContactStatus.ACTIVE;
    case TrustedContactStatus.REVOKED:
      return PrismaTrustedContactStatus.REVOKED;
    default:
      return PrismaTrustedContactStatus.PENDING;
  }
}

/**
 * Maps domain trusted contact data to Prisma create data
 * @param data The domain data
 * @returns The Prisma create data
 */
export function mapToPrismaCreateData(data: Partial<TrustedContact>): any {
  const createData: any = { ...data };

  if (data.status) {
    createData.status = mapToPrismaStatus(data.status);
  }

  return createData;
}

/**
 * Maps domain trusted contact data to Prisma update data
 * @param data The domain data
 * @returns The Prisma update data
 */
export function mapToPrismaUpdateData(data: Partial<TrustedContact>): any {
  const updateData: any = { ...data };

  if (data.status) {
    updateData.status = mapToPrismaStatus(data.status);
  }

  return updateData;
}
